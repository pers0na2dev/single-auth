package organization

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	ErrorOrganizationAlreadyExists      = "ORGANIZATION_ALREADY_EXISTS"
	ErrorOrganizationNotFound           = "ORGANIZATION_NOT_FOUND"
	ErrorUserAlreadyMember              = "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION"
	ErrorUserAlreadyInvited             = "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION"
	ErrorNoActiveOrganization           = "NO_ACTIVE_ORGANIZATION"
	ErrorMemberNotFound                 = "MEMBER_NOT_FOUND"
	ErrorOnlyOwner                      = "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"
	ErrorMemberDeleteForbidden          = "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER"
	ErrorOrganizationCreateForbidden    = "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION"
	ErrorOrganizationLimitReached       = "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS"
	ErrorOrganizationSlugTaken          = "ORGANIZATION_SLUG_ALREADY_TAKEN"
	ErrorUserNotOrganizationMember      = "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"
	ErrorOrganizationUpdateForbidden    = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION"
	ErrorOrganizationDeleteForbidden    = "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION"
	ErrorOrganizationDeletionDisabled   = "ORGANIZATION_DELETION_DISABLED"
	ErrorMemberUpdateForbidden          = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER"
	ErrorOrganizationWithoutOwner       = "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER"
	ErrorNotMemberOfOrganization        = "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION"
	ErrorRoleNotFound                   = "ROLE_NOT_FOUND"
	ErrorInvitationForbidden            = "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION"
	ErrorInvitationNotFound             = "INVITATION_NOT_FOUND"
	ErrorInvitationRecipientMismatch    = "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION"
	ErrorInvitationEmailUnverified      = "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION"
	ErrorInvitationListUnverified       = "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION"
	ErrorInvitationCancelForbidden      = "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION"
	ErrorInvitationCreatorRoleForbidden = "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE"
	ErrorInviterNoLongerMember          = "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION"
	ErrorMembershipLimitReached         = "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED"
	ErrorTeamNotFound                   = "TEAM_NOT_FOUND"
	ErrorInvalidTeamID                  = "INVALID_TEAM_ID"
	ErrorTeamCreateForbidden            = "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION"
	ErrorTeamDeleteForbidden            = "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION"
	ErrorTeamUpdateForbidden            = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM"
	ErrorTeamDeleteActiveForbidden      = "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM"
	ErrorMaximumTeamsReached            = "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS"
	ErrorUnableToRemoveLastTeam         = "UNABLE_TO_REMOVE_LAST_TEAM"
	ErrorOrganizationAccessForbidden    = "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION"
	ErrorUserNotTeamMember              = "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"
	ErrorNoActiveTeam                   = "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM"
	ErrorTeamMemberCreateForbidden      = "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER"
	ErrorTeamMemberRemoveForbidden      = "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER"
	ErrorTeamMemberLimitReached         = "TEAM_MEMBER_LIMIT_REACHED"
	ErrorMissingAccessControl           = "MISSING_AC_INSTANCE"
	ErrorRoleOrganizationRequired       = "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE"
	ErrorRoleCreateForbidden            = "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE"
	ErrorRoleUpdateForbidden            = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE"
	ErrorRoleDeleteForbidden            = "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE"
	ErrorRoleReadForbidden              = "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE"
	ErrorRoleListForbidden              = "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE"
	ErrorRoleGetForbidden               = "YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE"
	ErrorTooManyRoles                   = "TOO_MANY_ROLES"
	ErrorInvalidRoleResource            = "INVALID_RESOURCE"
	ErrorRoleNameTaken                  = "ROLE_NAME_IS_ALREADY_TAKEN"
	ErrorCannotDeletePredefinedRole     = "CANNOT_DELETE_A_PRE_DEFINED_ROLE"
	ErrorRoleAssignedToMembers          = "ROLE_IS_ASSIGNED_TO_MEMBERS"
)

var errorMessages = map[string]string{
	ErrorOrganizationAlreadyExists:      "Organization already exists",
	ErrorOrganizationNotFound:           "Organization not found",
	ErrorUserAlreadyMember:              "User is already a member of this organization",
	ErrorUserAlreadyInvited:             "User is already invited to this organization",
	ErrorNoActiveOrganization:           "No active organization",
	ErrorMemberNotFound:                 "Member not found",
	ErrorOnlyOwner:                      "You cannot leave the organization as the only owner",
	ErrorMemberDeleteForbidden:          "You are not allowed to delete this member",
	ErrorOrganizationCreateForbidden:    "You are not allowed to create a new organization",
	ErrorOrganizationLimitReached:       "You have reached the maximum number of organizations",
	ErrorOrganizationSlugTaken:          "Organization slug already taken",
	ErrorUserNotOrganizationMember:      "User is not a member of the organization",
	ErrorOrganizationUpdateForbidden:    "You are not allowed to update this organization",
	ErrorOrganizationDeleteForbidden:    "You are not allowed to delete this organization",
	ErrorOrganizationDeletionDisabled:   "Organization deletion is disabled",
	ErrorMemberUpdateForbidden:          "You are not allowed to update this member",
	ErrorOrganizationWithoutOwner:       "You cannot leave the organization without an owner",
	ErrorNotMemberOfOrganization:        "You are not a member of this organization",
	ErrorRoleNotFound:                   "Role not found",
	ErrorInvitationForbidden:            "You are not allowed to invite users to this organization",
	ErrorInvitationNotFound:             "Invitation not found",
	ErrorInvitationRecipientMismatch:    "You are not the recipient of the invitation",
	ErrorInvitationEmailUnverified:      "Email verification required before accepting or rejecting invitation",
	ErrorInvitationListUnverified:       "Email verification required to view or list invitations for the session email",
	ErrorInvitationCancelForbidden:      "You are not allowed to cancel this invitation",
	ErrorInvitationCreatorRoleForbidden: "You are not allowed to invite a user with this role",
	ErrorInviterNoLongerMember:          "Inviter is no longer a member of the organization",
	ErrorMembershipLimitReached:         "Organization membership limit reached",
	ErrorTeamNotFound:                   "Team not found",
	ErrorInvalidTeamID:                  "Team id contains a reserved character",
	ErrorTeamCreateForbidden:            "You are not allowed to create teams in this organization",
	ErrorTeamDeleteForbidden:            "You are not allowed to delete teams in this organization",
	ErrorTeamUpdateForbidden:            "You are not allowed to update this team",
	ErrorTeamDeleteActiveForbidden:      "You are not allowed to delete this team",
	ErrorMaximumTeamsReached:            "You have reached the maximum number of teams",
	ErrorUnableToRemoveLastTeam:         "Unable to remove last team",
	ErrorOrganizationAccessForbidden:    "You are not allowed to access this organization as an owner",
	ErrorUserNotTeamMember:              "User is not a member of the team",
	ErrorNoActiveTeam:                   "You do not have an active team",
	ErrorTeamMemberCreateForbidden:      "You are not allowed to create a new member",
	ErrorTeamMemberRemoveForbidden:      "You are not allowed to remove a team member",
	ErrorTeamMemberLimitReached:         "Team member limit reached",
	ErrorMissingAccessControl:           "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information",
	ErrorRoleOrganizationRequired:       "You must be in an organization to create a role",
	ErrorRoleCreateForbidden:            "You are not allowed to create a role",
	ErrorRoleUpdateForbidden:            "You are not allowed to update a role",
	ErrorRoleDeleteForbidden:            "You are not allowed to delete a role",
	ErrorRoleReadForbidden:              "You are not allowed to read a role",
	ErrorRoleListForbidden:              "You are not allowed to list a role",
	ErrorRoleGetForbidden:               "You are not allowed to get a role",
	ErrorTooManyRoles:                   "This organization has too many roles",
	ErrorInvalidRoleResource:            "The provided permission includes an invalid resource",
	ErrorRoleNameTaken:                  "That role name is already taken",
	ErrorCannotDeletePredefinedRole:     "Cannot delete a pre-defined role",
	ErrorRoleAssignedToMembers:          "Cannot delete a role that is assigned to members. Please reassign the members to a different role first",
}

func organizationError(status int, code string) *contract.APIError {
	return contract.NewAPIError(status, code, errorMessages[code])
}

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(errorMessages))
	for code, message := range errorMessages {
		result[code] = engine.ErrorDefinition{Message: message}
	}
	return result
}
