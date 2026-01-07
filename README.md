# fastscoop

A fast, drop-in replacement for `scoop search`.

## Installation

```batch
cargo install fastscoop
```

Or download a binary from [Releases](https://github.com/trypsynth/fastscoop/releases).

## Usage

```batch
fastscoop search <query>
```

The query is a case-insensitive regex. Searches package names and binary names across all local buckets.

## Output

The goal is to have the output be identical to existing Scoop commands, in order to make scripts able to remain unchanged once the binary is put in the right place and aliased. Fastscoop should only make Scoop faster, absolutely nothing more.

## License

[MIT](LICENSE)
