#![allow(non_snake_case)]

// macro list allows compile-time iteration

#[macro_export]
macro_rules! with_every_entity {
    ($callback:ident) => {
        $callback![
            AccessPolicy,
            AccessPolicyAction,
            ActionDefinition,
            ActionExecution,
            AdminRole,
            ApiToken,
            AuditMaintenanceMode,
            CertificateCredential,
            CertificateRevocation,
            FailedLoginAttempt,
            HttpSession,
            IpBlock,
            KnownHost,
            LdapServer,
            LogEntry,
            ManagedAccount,
            Node,
            OtpCredential,
            Parameters,
            PasswordCredential,
            PortalFavorite,
            PortalSavedView,
            PortalSavedViewShare,
            PortalSavedViewTarget,
            PublicKeyCredential,
            Recording,
            Role,
            Session,
            SshClientKey,
            SshCredential,
            SsoCredential,
            Target,
            TargetGroup,
            TargetLabel,
            TargetRoleAssignment,
            Ticket,
            TicketRequest,
            User,
            UserAdminRoleAssignment,
            UserGroup,
            UserGroupMember,
            UserLockout,
            UserRoleAssignment,
            WinrmCredential,
        ];
    };
}

macro_rules! declare_modules {
    ($($name:ident),* $(,)?) => {
        $( pub mod $name; )*
    };
}

with_every_entity!(declare_modules);
