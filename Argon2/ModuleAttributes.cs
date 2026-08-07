using System.Runtime.CompilerServices;

// The hashing/verification paths allocate short-lived buffers on the stack for
// passwords, salts and the encoded hash. Skipping the implicit zeroing of these
// locals is a small performance win, but more importantly it forces the code to
// never rely on locals-init zeroing for correctness (see Argon2PasswordHasher,
// where the encoded buffer and the verify null-terminator are handled
// explicitly). This keeps behavior identical whether or not a consumer compiles
// with SkipLocalsInit.
[module: SkipLocalsInit]
