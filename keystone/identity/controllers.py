# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Workflow Logic the Identity service."""

from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.common import utils
from keystone import exception
from keystone.i18n import _, _LW
from keystone.identity import schema
from keystone import notifications
import datetime

CONF = cfg.CONF
LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'identity_api', 'resource_api')
class User(controller.V2Controller):
    @controller.v2_deprecated
    def get_user(self, context, user_id):
        self.assert_admin(context)
        ref = self.identity_api.get_user(user_id)
        return {'user': self.v3_to_v2_user(ref)}

    @controller.v2_deprecated
    def get_users(self, context):
        # NOTE(termie): i can't imagine that this really wants all the data
        #               about every single user in the system...
        if 'name' in context['query_string']:
            return self.get_user_by_name(
                context, context['query_string'].get('name'))

        self.assert_admin(context)
        user_list = self.identity_api.list_users(
            CONF.identity.default_domain_id)
        return {'users': self.v3_to_v2_user(user_list)}

    @controller.v2_deprecated
    def get_user_by_name(self, context, user_name):
        self.assert_admin(context)
        ref = self.identity_api.get_user_by_name(
            user_name, CONF.identity.default_domain_id)
        return {'user': self.v3_to_v2_user(ref)}

    # CRUD extension
    @controller.v2_deprecated
    def create_user(self, context, user):
        user = self._normalize_OSKSADM_password_on_request(user)
        user = self.normalize_username_in_request(user)
        user = self._normalize_dict(user)
        self.assert_admin(context)

        if 'name' not in user or not user['name']:
            msg = _('Name field is required and cannot be empty')
            raise exception.ValidationError(message=msg)
        if 'enabled' in user and not isinstance(user['enabled'], bool):
            msg = _('Enabled field must be a boolean')
            raise exception.ValidationError(message=msg)

        default_project_id = user.pop('tenantId', None)
        if default_project_id is not None:
            # Check to see if the project is valid before moving on.
            self.resource_api.get_project(default_project_id)
            user['default_project_id'] = default_project_id

        # The manager layer will generate the unique ID for users
        user_ref = self._normalize_domain_id(context, user.copy())
        new_user_ref = self.v3_to_v2_user(
            self.identity_api.create_user(user_ref))

        if default_project_id is not None:
            self.assignment_api.add_user_to_project(default_project_id,
                                                    new_user_ref['id'])
        return {'user': new_user_ref}

    @controller.v2_deprecated
    def update_user(self, context, user_id, user):
        # NOTE(termie): this is really more of a patch than a put
        user = self.normalize_username_in_request(user)
        self.assert_admin(context)

        if 'enabled' in user and not isinstance(user['enabled'], bool):
            msg = _('Enabled field should be a boolean')
            raise exception.ValidationError(message=msg)

        default_project_id = user.pop('tenantId', None)
        if default_project_id is not None:
            user['default_project_id'] = default_project_id

        old_user_ref = self.v3_to_v2_user(
            self.identity_api.get_user(user_id))

        # Check whether a tenant is being added or changed for the user.
        # Catch the case where the tenant is being changed for a user and also
        # where a user previously had no tenant but a tenant is now being
        # added for the user.
        if (('tenantId' in old_user_ref and
                     old_user_ref['tenantId'] != default_project_id and
                     default_project_id is not None) or
                ('tenantId' not in old_user_ref and
                         default_project_id is not None)):
            # Make sure the new project actually exists before we perform the
            # user update.
            self.resource_api.get_project(default_project_id)

        user_ref = self.v3_to_v2_user(
            self.identity_api.update_user(user_id, user))

        # If 'tenantId' is in either ref, we might need to add or remove the
        # user from a project.
        if 'tenantId' in user_ref or 'tenantId' in old_user_ref:
            if user_ref['tenantId'] != old_user_ref.get('tenantId'):
                if old_user_ref.get('tenantId'):
                    try:
                        member_role_id = CONF.member_role_id
                        self.assignment_api.remove_role_from_user_and_project(
                            user_id, old_user_ref['tenantId'], member_role_id)
                    except exception.NotFound:
                        # NOTE(morganfainberg): This is not a critical error it
                        # just means that the user cannot be removed from the
                        # old tenant.  This could occur if roles aren't found
                        # or if the project is invalid or if there are no roles
                        # for the user on that project.
                        msg = _LW('Unable to remove user %(user)s from '
                                  '%(tenant)s.')
                        LOG.warning(msg, {'user': user_id,
                                          'tenant': old_user_ref['tenantId']})

                if user_ref['tenantId']:
                    try:
                        self.assignment_api.add_user_to_project(
                            user_ref['tenantId'], user_id)
                    except exception.Conflict:
                        # We are already a member of that tenant
                        pass
                    except exception.NotFound:
                        # NOTE(morganfainberg): Log this and move on. This is
                        # not the end of the world if we can't add the user to
                        # the appropriate tenant. Most of the time this means
                        # that the project is invalid or roles are some how
                        # incorrect.  This shouldn't prevent the return of the
                        # new ref.
                        msg = _LW('Unable to add user %(user)s to %(tenant)s.')
                        LOG.warning(msg, {'user': user_id,
                                          'tenant': user_ref['tenantId']})

        return {'user': user_ref}

    @controller.v2_deprecated
    def delete_user(self, context, user_id):
        self.assert_admin(context)
        self.identity_api.delete_user(user_id)

    @controller.v2_deprecated
    def set_user_enabled(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    @controller.v2_deprecated
    def set_user_password(self, context, user_id, user):
        user = self._normalize_OSKSADM_password_on_request(user)
        return self.update_user(context, user_id, user)

    @staticmethod
    def _normalize_OSKSADM_password_on_request(ref):
        """Sets the password from the OS-KSADM Admin Extension.

        The OS-KSADM Admin Extension documentation says that
        `OS-KSADM:password` can be used in place of `password`.

        """
        if 'OS-KSADM:password' in ref:
            ref['password'] = ref.pop('OS-KSADM:password')
        return ref


@dependency.requires('identity_api')
class UserV3(controller.V3Controller):
    collection_name = 'users'
    member_name = 'user'

    def __init__(self):
        super(UserV3, self).__init__()
        self.get_member_from_driver = self.identity_api.get_user

    def _check_user_and_group_protection(self, context, prep_info,
                                         user_id, group_id):
        ref = {}
        ref['user'] = self.identity_api.get_user(user_id)
        ref['group'] = self.identity_api.get_group(group_id)
        self.check_protection(context, prep_info, ref)

    # rrawat: Function to check password policy. Policy configuration in config.py
    def checkPasswordPolicy(self, password):
        num_uppercase = CONF.password_policy.num_uppercase
        num_lowercase = CONF.password_policy.num_lowercase
        num_specialchars = CONF.password_policy.num_specialchars
        num_numeric = CONF.password_policy.num_numeric
        min_length = CONF.password_policy.min_length
        max_length = CONF.password_policy.max_length
        if (min_length != -1) and (len(password) < min_length):
            return False
        if (max_length != -1) and (len(password) > max_length):
            return False
        if (num_lowercase != -1) and (sum(1 for c in password if c.islower()) < num_lowercase):
            return False
        if (num_uppercase != -1) and (sum(1 for c in password if c.isupper()) < num_uppercase):
            return False
        if (num_numeric != -1) and (sum(1 for c in password if c.isdigit()) < num_numeric):
            return False
        if (num_specialchars != -1) and (sum(1 for c in password if not c.isalnum()) < num_specialchars):
            return False

        return True

    @controller.protected()
    @validation.validated(schema.user_create, 'user')
    def create_user(self, context, user):
        # The manager layer will generate the unique ID for users
        expiry_days = CONF.password_policy.expiry_days
        user['expiry'] = datetime.datetime.now() + datetime.timedelta(days=expiry_days)
        ref = self._normalize_dict(user)
        ref = self._normalize_domain_id(context, ref)
        initiator = notifications._get_request_audit_info(context)
        password = user.get('password')
        if password is not None:
            if not self.checkPasswordPolicy(password):
                raise exception.ValidationError(target='user',
                                                attribute='password',
                                               message='password does not validate password policy')
        ref = self.identity_api.create_user(ref, initiator)
        return UserV3.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'enabled', 'name')
    def list_users(self, context, filters):
        hints = UserV3.build_driver_hints(context, filters)
        refs = self.identity_api.list_users(
            domain_scope=self._get_domain_id_for_list_request(context),
            hints=hints)
        return UserV3.wrap_collection(context, refs, hints=hints)

    @controller.filterprotected('domain_id', 'enabled', 'name')
    def list_users_in_group(self, context, filters, group_id):
        hints = UserV3.build_driver_hints(context, filters)
        refs = self.identity_api.list_users_in_group(group_id, hints=hints)
        return UserV3.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_user(self, context, user_id):
        ref = self.identity_api.get_user(user_id)
        return UserV3.wrap_member(context, ref)

    def _update_user(self, context, user_id, user):
        self._require_matching_id(user_id, user)
        self._require_matching_domain_id(
            user_id, user, self.identity_api.get_user)
        initiator = notifications._get_request_audit_info(context)
        ref = self.identity_api.update_user(user_id, user, initiator)
        return UserV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.user_update, 'user')
    def update_user(self, context, user_id, user):
        return self._update_user(context, user_id, user)

    @controller.protected(callback=_check_user_and_group_protection)
    def add_user_to_group(self, context, user_id, group_id):
        self.identity_api.add_user_to_group(user_id, group_id)

    @controller.protected(callback=_check_user_and_group_protection)
    def check_user_in_group(self, context, user_id, group_id):
        return self.identity_api.check_user_in_group(user_id, group_id)

    @controller.protected(callback=_check_user_and_group_protection)
    def remove_user_from_group(self, context, user_id, group_id):
        self.identity_api.remove_user_from_group(user_id, group_id)

    @controller.protected()
    def delete_user(self, context, user_id):
        initiator = notifications._get_request_audit_info(context)
        return self.identity_api.delete_user(user_id, initiator)

    def match_previous_passwords(self, user_id, password):
        user_history = self.identity_api.get_user_history(user_id)
        if user_history:
            for x in user_history:
                if utils.check_password(password=password, hashed=x.password):
                    return True

        return False

    @controller.protected()
    def change_password(self, context, user_id, user):
        original_password = user.get('original_password')
        if original_password is None:
            raise exception.ValidationError(target='user',
                                            attribute='original_password')

        password = user.get('password')
        if password is None:
            raise exception.ValidationError(target='user',
                                            attribute='password')
        if not self.checkPasswordPolicy(password):
            raise exception.ValidationError(target='user',
                                            attribute='password',
                                            message='password is not in correct format.')
        if original_password == password:
            raise exception.ValidationError(target='user',
                                            attribute='password',
                                            message='Cannot use same password.')
        if self.match_previous_passwords(user_id, password):
            raise exception.ValidationError(target='user',
                                            attribute='password',
                                            message='Cannot use old passwords')

        try:
            self.identity_api.change_password(
                context, user_id, original_password, password)
        except AssertionError:
            raise exception.Unauthorized()


@dependency.requires('identity_api')
class GroupV3(controller.V3Controller):
    collection_name = 'groups'
    member_name = 'group'

    def __init__(self):
        super(GroupV3, self).__init__()
        self.get_member_from_driver = self.identity_api.get_group

    @controller.protected()
    @validation.validated(schema.group_create, 'group')
    def create_group(self, context, group):
        # The manager layer will generate the unique ID for groups
        ref = self._normalize_dict(group)
        ref = self._normalize_domain_id(context, ref)
        initiator = notifications._get_request_audit_info(context)
        ref = self.identity_api.create_group(ref, initiator)
        return GroupV3.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'name')
    def list_groups(self, context, filters):
        hints = GroupV3.build_driver_hints(context, filters)
        refs = self.identity_api.list_groups(
            domain_scope=self._get_domain_id_for_list_request(context),
            hints=hints)
        return GroupV3.wrap_collection(context, refs, hints=hints)

    @controller.filterprotected('name')
    def list_groups_for_user(self, context, filters, user_id):
        hints = GroupV3.build_driver_hints(context, filters)
        refs = self.identity_api.list_groups_for_user(user_id, hints=hints)
        return GroupV3.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_group(self, context, group_id):
        ref = self.identity_api.get_group(group_id)
        return GroupV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.group_update, 'group')
    def update_group(self, context, group_id, group):
        self._require_matching_id(group_id, group)
        self._require_matching_domain_id(
            group_id, group, self.identity_api.get_group)
        initiator = notifications._get_request_audit_info(context)
        ref = self.identity_api.update_group(group_id, group, initiator)
        return GroupV3.wrap_member(context, ref)

    @controller.protected()
    def delete_group(self, context, group_id):
        initiator = notifications._get_request_audit_info(context)
        self.identity_api.delete_group(group_id, initiator)
