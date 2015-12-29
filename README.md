# memchunkhax2

WIP implementation of the ARM11 kernel exploit described [here](https://www.youtube.com/watch?v=CzVZgdkzBn8). Currently overwrites the memory block header next pointer, but freezes due to being pointed at an invalid location.

Currently requires [this pull request](https://github.com/smealum/ctrulib/pull/235) to ctrulib.
