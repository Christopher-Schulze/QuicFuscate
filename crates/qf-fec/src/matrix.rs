//! Checked GF(2^8) matrix multiplication used by FEC parity tests and adapters.

/// Errors returned by checked matrix multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum MatrixError {
    EmptyInput,
    RaggedA,
    RaggedB,
    RaggedResult,
    DimensionMismatch,
    DimensionOverflow,
}

impl std::fmt::Display for MatrixError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyInput => "FEC matrix inputs must be nonempty",
            Self::RaggedA => "FEC matrix A is ragged",
            Self::RaggedB => "FEC matrix B is ragged",
            Self::RaggedResult => "FEC matrix result is ragged",
            Self::DimensionMismatch => "FEC matrix dimensions do not match",
            Self::DimensionOverflow => "FEC matrix dimensions overflow",
        })
    }
}

impl std::error::Error for MatrixError {}

/// Compute `C = A x B` over GF(2^8) with XOR addition.
#[inline]
#[doc(hidden)]
pub fn matrix_multiply_scalar(
    a: &[Vec<u8>],
    b: &[Vec<u8>],
    result: &mut [Vec<u8>],
) -> Result<(), MatrixError> {
    let a_cols = a.first().ok_or(MatrixError::EmptyInput)?.len();
    let b_cols = b.first().ok_or(MatrixError::EmptyInput)?.len();
    let result_cols = result.first().ok_or(MatrixError::EmptyInput)?.len();
    if a_cols == 0 || b_cols == 0 || result_cols == 0 {
        return Err(MatrixError::EmptyInput);
    }
    if a.iter().any(|row| row.len() != a_cols) {
        return Err(MatrixError::RaggedA);
    }
    if b.iter().any(|row| row.len() != b_cols) {
        return Err(MatrixError::RaggedB);
    }
    if result.iter().any(|row| row.len() != result_cols) {
        return Err(MatrixError::RaggedResult);
    }
    if a_cols != b.len() || result.len() != a.len() || result_cols != b_cols {
        return Err(MatrixError::DimensionMismatch);
    }
    a.len()
        .checked_mul(a_cols)
        .and_then(|_| a_cols.checked_mul(b_cols))
        .and_then(|_| a.len().checked_mul(b_cols))
        .ok_or(MatrixError::DimensionOverflow)?;

    crate::gf_tables::init_tables();
    let m = a.len();
    let k = a[0].len();
    for row in result.iter_mut() {
        row.fill(0);
    }
    for (column, b_row) in b.iter().take(k).enumerate() {
        for (row_index, result_row) in result.iter_mut().enumerate().take(m) {
            let coefficient = a[row_index][column];
            if coefficient != 0 {
                crate::gf_tables::gf_mul_scalar_slice(coefficient, b_row, result_row);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{matrix_multiply_scalar, MatrixError};

    #[test]
    fn malformed_shapes_fail_closed() {
        let mut result = vec![vec![0u8; 1]];
        assert_eq!(
            matrix_multiply_scalar(&[], &[vec![1]], &mut result),
            Err(MatrixError::EmptyInput)
        );
        assert_eq!(
            matrix_multiply_scalar(&[vec![1], vec![]], &[vec![1]], &mut result),
            Err(MatrixError::RaggedA)
        );
        assert_eq!(
            matrix_multiply_scalar(&[vec![1, 2]], &[vec![1], vec![2, 3]], &mut result),
            Err(MatrixError::RaggedB)
        );
        assert_eq!(
            matrix_multiply_scalar(&[vec![1]], &[vec![1]], &mut [vec![0], vec![0]]),
            Err(MatrixError::DimensionMismatch)
        );
        assert_eq!(
            matrix_multiply_scalar(&[vec![1]], &[vec![1]], &mut [vec![0, 0], vec![0]]),
            Err(MatrixError::RaggedResult)
        );

        let mut valid = vec![vec![0u8; 1]];
        matrix_multiply_scalar(&[vec![1, 2]], &[vec![3], vec![4]], &mut valid)
            .expect("valid matrix dimensions");
        assert_eq!(valid, vec![vec![11]]);
    }
}
