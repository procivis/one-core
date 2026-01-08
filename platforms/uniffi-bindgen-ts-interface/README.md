# uniffi-bindgen-ts-interface

`uniffi-bindgen-ts-interface` is an experimental [uniffi](https://mozilla.github.io/uniffi-rs/latest/)
bindgen for typescript. It's based on [uniffi-bindgen-node](https://github.com/livekit/uniffi-bindgen-node). It generates typescript interfaces only, no real code. So cannot be used directly but only as a build tool in a larger project.

> [!WARNING]
> uniffi-bindgen-ts-interface is a work in progress, and doesn't yet support the whole uniffi ffi specification.
>
> Implemented features:
>
> - Records
> - Regular function calling
> - Async function calling
> - Enums (both bare enums and enums with associated fields)
> - Traits (including TS -> rust function calls support)
> - Error enums / exceptions
>
> Currently missing features:
>
> - Objects (multiple constructors, async + regular method calling)
> - Any sort of comprehensive test suite

## Installation (for local development)

1. Clone this repository
2. Run `cargo install --path .`
3. `uniffi-bindgen-ts-interface` should be in `~/.cargo/bin` - make sure this is part of your `PATH`.

## Usage

Run `uniffi-bindgen-ts-interface --library <lib_path>`, passing a dynamic library (`dylib`/`dll`/`so`) build to
export a uniffi interface. See `output/` for the results. For more complicated scenarios, run
`uniffi-bindgen-ts-interface --help`.
