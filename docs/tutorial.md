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

Retrieve a product summary
> griffon service product-summary -s rhel-7.6.z
> griffon --format json service product-summary -s rhel-7.6.z

Retrieve a product manifest
> griffon service product-components rhel-9.0.0.z

Retrieve a spdx json formatted product manifest
> griffon service product-manifest ansible_automation_platform-2.3 --spdx-json

