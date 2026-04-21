---
description: Testing standards and test structure guidelines
globs: ["**/*.test.ts", "**/*.test.tsx", "**/*.spec.ts", "**/*.spec.tsx", "**/tests/**", "**/__tests__/**"]
---

# Testing Standards

## Test Pyramid

```
         /\
        /  \     E2E (few)
       /────\    
      /      \   Integration (some)
     /────────\  
    /          \ Unit (many)
   /────────────\
```

- **Unit tests**: Fast, isolated, many
- **Integration tests**: Test modules together
- **E2E tests**: Critical user paths only

## Test Structure (AAA)

```typescript
it('should calculate total with discount', () => {
  // Arrange - Setup data
  const cart = new Cart();
  cart.addItem({ price: 100, quantity: 2 });
  
  // Act - Execute code
  const total = cart.calculateTotal(0.1);
  
  // Assert - Verify result
  expect(total).toBe(180);
});
```

## What to Test

### Always Test

- Public APIs and functions
- Business logic
- Edge cases and error handling
- Data transformations

### Don't Test

- Private methods (test through public API)
- Framework/library code
- Third-party integrations (mock them)
- Simple getters/setters

## Mocking

**When to Mock:**
- External services (APIs, databases)
- Time-dependent code
- Random values
- File system operations

**When NOT to Mock:**
- The code under test
- Simple pure functions
- Data structures
