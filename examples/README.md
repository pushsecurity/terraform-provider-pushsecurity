# Examples

Directory layout is what `tfplugindocs` expects, so these files are both
runnable examples and the source of the code blocks in `docs/`:

```
provider/provider.tf              docs/index.md
resources/<name>/resource.tf      docs/resources/<name>.md
resources/<name>/import.sh        the import section of that page
data-sources/<name>/data-source.tf  docs/data-sources/<name>.md
```
