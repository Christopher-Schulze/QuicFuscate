//! Intel AMX integration boundary.
//!
//! The former raw AMX kernels were removed from the active build because the
//! GF(256) path performed scalar coefficient multiplication after tile
//! load/store, and the standalone INT8 kernel had no valid shape or tile
//! register contract. The production Wiedemann path therefore uses its
//! checked scalar GF(256) fallback and reports no AMX operations. TODO-818
//! owns a future AMX implementation and its compiler/runtime proof lane.
