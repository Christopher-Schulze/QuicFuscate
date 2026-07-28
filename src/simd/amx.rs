//! Extracted SIMD `amx` submodule (TODO-563).

use std::arch::asm;

const TILE_BYTES: usize = 64;
const TILE_ROWS_0: u8 = 16;
const TILE_COLS_0: u16 = 64;

#[repr(C, align(64))]
struct TileConfig {
    palette_id: u8,
    start_row: u8,
    reserved: [u8; 14],
    colsb: [u16; 8],
    rows: [u8; 8],
    reserved2: [u8; 24],
}

impl TileConfig {
    const fn new() -> Self {
        Self {
            palette_id: 1,
            start_row: 0,
            reserved: [0u8; 14],
            colsb: [0u16; 8],
            rows: [0u8; 8],
            reserved2: [0u8; 24],
        }
    }

    fn configure(&mut self, rows: u8, cols: u16) {
        self.palette_id = 1;
        self.start_row = 0;
        self.colsb = [0u16; 8];
        self.rows = [0u8; 8];
        self.colsb[0] = cols;
        self.rows[0] = rows;
        // Clear remaining slots for safety
        for slot in 1..8 {
            self.colsb[slot] = 0;
            self.rows[slot] = 0;
        }
    }
}

static mut TILE_CONFIG: TileConfig = TileConfig::new();

/// Configure AMX tiles for the canonical 16x64 layout used in GF(256) blocks.
#[target_feature(enable = "amx-tile")]
pub(super) unsafe fn amx_init() {
    TILE_CONFIG.configure(TILE_ROWS_0, TILE_COLS_0);
    asm!(
        "ldtilecfg [{cfg}]",
        cfg = in(reg) &TILE_CONFIG as *const TileConfig,
        options(nostack)
    );
}

/// Release AMX tiles after use.
#[target_feature(enable = "amx-tile")]
pub(super) unsafe fn amx_release() {
    asm!("tilerelease", options(nostack));
}

/// Matrix multiply with Intel AMX
#[target_feature(enable = "amx-int8")]
pub(super) unsafe fn amx_matmul_i8(
    a: &[i8],
    b: &[i8],
    c: &mut [i32],
    m: usize,
    k: usize,
    n: usize,
) {
    use std::arch::asm;

    amx_init();

    // Load tiles and perform multiplication
    asm!(
        "tileloadd tmm0, [{}]",
        "tileloadd tmm1, [{}]",
        "tdpbssd tmm2, tmm0, tmm1",
        "tilestored [{}], tmm2",
        in(reg) a.as_ptr(),
        in(reg) b.as_ptr(),
        in(reg) c.as_mut_ptr(),
        options(nostack)
    );

    // Release tiles
    asm!("tilerelease", options(nostack));
}

/// GF(256) matrix x vector multiply specialised for Wiedemann solver.
#[target_feature(enable = "amx-int8")]
pub(super) unsafe fn matmul_gf256_amx(
    matrix: &[u8],
    vector: &[u8],
    output: &mut [u8],
    rows: usize,
    cols: usize,
    _out_cols: usize,
) {
    use crate::fec::gf_tables;

    const TILE_ROWS: usize = 16;
    const TILE_COLS: usize = 64;

    if rows == 0 || cols == 0 {
        return;
    }

    amx_init();
    let mut tile_buf = [0u8; TILE_ROWS * TILE_COLS];

    for row_block in (0..rows).step_by(TILE_ROWS) {
        let block_rows = usize::min(TILE_ROWS, rows - row_block);
        for col_block in (0..cols).step_by(TILE_COLS) {
            let block_cols = usize::min(TILE_COLS, cols - col_block);

            if block_rows == TILE_ROWS && block_cols == TILE_COLS {
                let src = matrix.as_ptr().add(row_block * cols + col_block);
                asm!(
                    "tileloadd tmm0, [{src}]",
                    src = in(reg) src,
                    options(nostack)
                );
                asm!(
                    "tilestored [{dst}], tmm0",
                    dst = in(reg) tile_buf.as_mut_ptr(),
                    options(nostack)
                );
            } else {
                for r in 0..block_rows {
                    let src = matrix.as_ptr().add((row_block + r) * cols + col_block);
                    let dst = tile_buf.as_mut_ptr().add(r * TILE_COLS);
                    std::ptr::copy_nonoverlapping(src, dst, block_cols);
                }
            }

            for r in 0..block_rows {
                let mut acc = if col_block == 0 { 0u8 } else { output[row_block + r] };

                let row_slice = &tile_buf[r * TILE_COLS..r * TILE_COLS + block_cols];
                for (idx, &val) in row_slice.iter().enumerate() {
                    let coeff = vector[col_block + idx];
                    if val != 0 && coeff != 0 {
                        acc ^= gf_tables::gf_mul_table(val, coeff);
                    }
                }

                output[row_block + r] = acc;
            }
        }
    }

    amx_release();
}
