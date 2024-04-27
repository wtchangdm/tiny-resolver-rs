use std::io;

#[derive(Debug)]
pub enum Error {
    InvalidHostname,
    NetworkError(io::Error),
    ResolverError(String),
    // The following error are from name servers
    ServerError(NameServerError),
}

#[derive(Debug)]
pub enum NameServerError {
    NxDomain = 1,
    ServerFailure = 2,
    FormatError = 3,
    NotImplemented = 4,
    Refused = 5,
    Unknown = 6,
}

impl From<u16> for NameServerError {
    fn from(value: u16) -> NameServerError {
        match value {
            1 => NameServerError::NxDomain,
            2 => NameServerError::ServerFailure,
            3 => NameServerError::FormatError,
            4 => NameServerError::NotImplemented,
            5 => NameServerError::Refused,
            _ => NameServerError::Unknown,
        }
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::InvalidHostname, Error::InvalidHostname) => true,
            (Error::ServerError(_), Error::ServerError(_)) => true,
            (Error::NetworkError(_), Error::NetworkError(_)) => false,
            _ => false,
        }
    }
}
