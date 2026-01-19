use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Admin,
    User,
    Anonymous,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Role::Admin => "Admin",
            Role::User => "User",
            Role::Anonymous => "Anon",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    pub role: Role,
    pub token: Option<String>,
    pub header_name: String,
}

impl RoleConfig {
    pub fn new(role: Role, token: Option<String>, header_name: String) -> Self {
        Self {
            role,
            token,
            header_name,
        }
    }
}

impl PartialEq for RoleConfig {
    fn eq(&self, other: &Self) -> bool {
        self.role == other.role
    }
}

impl Eq for RoleConfig {}

impl Hash for RoleConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.role.hash(state);
    }
}
