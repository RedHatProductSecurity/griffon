## Tutorial (UNDER DEVELOPMENT)

Find Products that contain latest root Component(s)  
> griffon service products-contain-component webkitgtk
Use -s flag for stricter search
> griffon service products-contain-component -s webkitgtk

And regex expressions
> griffon service products-contain-component "^webkitgtk(\d)$"

Use of -v (up to -vvvv) to get more information
> griffon service products-contain-component "^webkitgtk(\d)"
> griffon -v service products-contain-component "^webkitgtk(\d)"
> griffon -vv service products-contain-component "^webkitgtk(\d)"
> griffon -vvv service products-contain-component "^webkitgtk(\d)"
> griffon -vvvv service products-contain-component "^webkitgtk(\d)"

Find Products that contain latest root Component(s) searching both root and dependencies
> griffon service products-contain-component webkitgtk --search-all
> griffon service products-contain-component github.com/go-redis/redis/v8/internal/hscan --search-all      

Find Products that contain latest root Component searching both root and related_url
> griffon service products-contain-component webkitgtk --search-related-url

Retrieve a Product summary
> griffon service product-summary -s rhel-7.6.z
> griffon --format json service product-summary -s rhel-7.6.z

Retrieve a Product latest root Components
> griffon service product-components rhel-9.0.0.z

Retrieve Product manifest containing latest root Components and dependencies
> griffon service product-manifest ansible_automation_platform-2.3 --spdx-json

Retrieve a spdx json formatted Product manifest
> griffon service product-manifest ansible_automation_platform-2.3 --spdx-json

Retrieve Component flaws
> griffon service component-flaws python-marshmallow 

Retrieve Product flaws
> griffon service product-flaws ansible_automation_platform-2 --affectedness AFFECTED --affect-resolution FIX

Retrieve Component summary
> griffon service component-summary python-marshmallow 

## Common questions

Given a CVE ID, what products are affected?
> griffon service products-affected-by-flaw CVE-2023-25166    

Given a CVE ID, what components are affected?
> griffon service components-affected-by-flaw CVE-2023-25166 

What products + version + stream contain a given component (e.g. full
text search)?
> griffon service products-contain-component --purl "pkg:rpm/curl@7.15.5"
> griffon service products-contain-component is-svg --search-all

Which unfixed CVE are affecting a component ?
> griffon service component-flaws --affectedness AFFECTED webkitgtk

Which unfixed CVE are affecting a product + version + stream ?
> griffon service product-flaws ansible_platform_2

What are the fixed CVE of this a product + version + stream?
> griffon service product-flaws rhel-9 --flaw-state DONE

What are the fixed CVEs for a component?
> griffon service component-flaws webkitgtk --flaw-state DONE

What are the won’t fix CVEs for a component?
> griffon service component-flaws webkitgtk --flaw-resolution WONTFIX

What are the won’t fix CVEs for a product?
> griffon service product-flaws rhel-9 --flaw-resolution WONTFIX

How many CVE’s are filed against a product + version
> griffon service product-flaws rhel-9 | wc -l
