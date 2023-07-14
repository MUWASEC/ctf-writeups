nc challenges1.hexionteam.com 3000
Note: flag is in ./flag

# solution
> srand bypass by loading same libc
> one byte overflow overwrite construct hangmanGame->wordLen
> hangmanGame->wordLen == game->size, classic bof
> ret2libc
