## Tutorial (UNDER DEVELOPMENT)

Find products a (latest) Component is in
> griffon service products-contain-component webkitgtk

One may use the -s flag for strict search
> griffon service products-contain-component -s webkitgtk

And regex expressions
> griffon service products-contain-component "^webkitgtk(\d)$"

Use of -v (up to -vvvv) to get more information
> griffon service products-contain-component "^webkitgtk(\d)"
> griffon -v service products-contain-component "^webkitgtk(\d)"
> griffon -vv service products-contain-component "^webkitgtk(\d)"
> griffon -vvv service products-contain-component "^webkitgtk(\d)"
> griffon -vvvv service products-contain-component "^webkitgtk(\d)"

