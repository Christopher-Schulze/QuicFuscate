let nextTestIdentity = 0;

export function createDeterministicTestUuid(): string {
  const value = nextTestIdentity;
  nextTestIdentity += 1;
  return `test-uuid-${value.toString(16).padStart(8, "0")}`;
}
