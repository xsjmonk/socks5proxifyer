# Native destination policy integration seam

This folder owns the native `ipRanges` enforcement boundary. Upstream merges
should touch only the narrow integration points listed here.

## Ownership

| File | Role |
|------|------|
| `process_key.h` | Single owner of canonical process-key normalization (header-only `inline`). |
| `dest_inclusion_policy.h/.cpp` | CIDR store, parse/match logic, and exported `dip_*` API. |
| `../socksify_unmanaged.cpp` | Thin adapter; forwards managed calls to `dip_*`. |

Do not duplicate `normalize_process_key` elsewhere. Do not move this policy into
`netlib`, managed configuration, or the router.

## Production project entries (`socksify/socksify.vcxproj`)

Required additions only:

- `ClInclude`: `policy\process_key.h`
- existing `ClInclude`: `policy\dest_inclusion_policy.h`
- existing `ClCompile`: `policy\dest_inclusion_policy.cpp`

No separate `process_key.cpp` compile item. The helper is linked through
`dest_inclusion_policy.cpp`, which includes `process_key.h`.

## Integration seam in `dest_inclusion_policy.cpp`

After upstream merges, ensure these three call sites still use the shared helper:

1. `dip_add_process()` storage key
2. `dip_remove_process()` storage key
3. `PolicyStore::should_redirect()` lookup key

Expected pattern:

```cpp
#include "policy/process_key.h"
// ...
using dip_policy::normalize_process_key;
```

## Native policy tests (outside the main solution)

The standalone project `socksify/tests/dest_inclusion_policy_test.vcxproj`
compiles `dest_inclusion_policy_test.cpp` plus production
`dest_inclusion_policy.cpp` for in-process API coverage. It is **not** registered
in `socksify.sln` to reduce solution merge conflicts.

Run:

```powershell
powershell -File scripts/Test-DestInclusionPolicy.ps1
```

Optional runtime validation:

```powershell
powershell -File scripts/Test-AppConfigIpRangesRuntime.ps1 -ConfigurationPath "R:\app-config.json"
powershell -File scripts/Test-IpRangesRuntimeAcceptance.ps1 -ConfigurationPath "R:\app-config.json"
```
