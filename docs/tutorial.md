## Tutorial

## Example queries

griffon service queries get-product-contain-component --name is-svg | jq '.results[].name' | sort | uniq
griffon service queries get-product-contain-component --purl "pkg:npm/is-svg@2.1.0" | jq ".product_streams[].name" | sort | uniq 