/// A bootstrap identifier is discoverable, but is not an accepted schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaStatus {
    ReservedUnreleased,
}

impl SchemaStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReservedUnreleased => "reserved-unreleased",
        }
    }

    pub const fn accepts_documents(self) -> bool {
        false
    }
}

/// A schema name recorded by the approved bootstrap contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaDescriptor {
    id: &'static str,
    status: SchemaStatus,
}

impl SchemaDescriptor {
    pub const fn id(self) -> &'static str {
        self.id
    }

    pub const fn status(self) -> SchemaStatus {
        self.status
    }
}

const RESERVED_SCHEMAS: [SchemaDescriptor; 14] = [
    SchemaDescriptor {
        id: "fenrua.approval.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.audit-event.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.authority-policy.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.compatibility-profile.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.decision.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.entity-manifest.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.evidence-bundle.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.key-metadata.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.key-rotation.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.receipt.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.revocation-set.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.tool-call-request.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.verification-result.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
    SchemaDescriptor {
        id: "fenrua.verification-vector.v1",
        status: SchemaStatus::ReservedUnreleased,
    },
];

/// Returns only bootstrap-reserved names. The R1 foundation accepts no schema
/// documents and therefore does not implement validation dispatch yet.
pub const fn reserved_schemas() -> &'static [SchemaDescriptor] {
    &RESERVED_SCHEMAS
}
