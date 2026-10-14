# Component analysis import

**Export inventory + AI template** saves the selected inventory JSON and a uniquely named sibling `*-ai-*` folder containing:

- `inventory.json`: a copy of the complete source inventory, including current selections.
- `analysis-template.json`: the matching image and every component identity/state, defaulting to `Review`, with `IsTemplate: true`.
- `README-AI.md`: self-contained format instructions, limitations and import steps.
- `PROMPT-CS2.md`: ready-to-use prompt for a dedicated CS2 DX11 competition PC (9850X3D / RTX 5000 series), accepting loss of unrelated functionality. The template Profile includes this scope.

Give all four files to an AI. The completed file must set `IsTemplate` to `false` and remain plain JSON. The importer explicitly rejects HTML (even renamed to JSON), Markdown code fences, original inventories and unfinished templates with actionable messages. Invalid imports preserve the current analysis and selections. Large JSON parsing/matching runs away from the UI thread.

In Custom mode, inspect an edition and load **List all components**. Use **Import analysis (.json)** to attach recommendations. Import validates the complete document before changing the displayed analysis or selections. A valid import immediately checks each matched `Remove` or `Disable` recommendation and sets its action.

Import adds these actions to the existing plan. It preserves removal groups, Core pruning, and other manual selections. `Keep`, `Review`, and unlisted entries do not change existing selections; they are recommendations, not protection locks. A selected group or Core pruning can still remove an item marked `Keep`. Clear existing selections first if you want to start from the analysis alone. Nothing is removed until a build is started.

Matching is case-sensitive and exact on `Kind` + `Identity`. Architecture, full version, edition, image index and installation type must match. Unknown/duplicate entries, unsupported actions and actions against absent capabilities are rejected. Partial reports are allowed; unlisted entries retain their current selection. The importer is not a dependency solver.

```json
{
  "SchemaVersion": 1,
  "ReportType": "Tiny11Builder.RemovalAnalysis",
  "IsTemplate": false,
  "Image": {
    "Index": 4,
    "Name": "Windows 11 专业版",
    "Description": "Windows 11 专业版",
    "Architecture": "x64",
    "Version": "10.0.22621.4169",
    "Edition": "Professional",
    "Installation": "Client",
    "Size": 20210877714
  },
  "Profile": "CS2 DX11 / Steam desktop",
  "Components": [
    {
      "Kind": "Service",
      "Identity": "DiagTrack",
      "Group": "诊断与遥测",
      "Purpose": "系统诊断遥测服务",
      "Dependencies": "精确服务依赖没有包含在原始清单中。",
      "RemovalImpact": "相关诊断遥测不可用。",
      "Recommendation": "Disable",
      "Reason": "目标用途不需要；禁用而不删除服务键。",
      "Confidence": "中",
      "Evidence": "服务标识与功能知识；未做此镜像运行验证。"
    }
  ]
}
```

Recommendations:

| Value | Effect on applying recommendations |
|---|---|
| `Keep` | Does not add an action; existing selections remain |
| `Review` | Does not add an action; existing selections remain |
| `Remove` | Immediately selects Remove for the matched item |
| `Disable` | Immediately selects Disable; only valid for Service and Feature |

Kinds: `ProvisionedApp`, `SystemApp`, `Feature`, `Capability`, `Package`, `Service`, `ComponentPayload`. Use the original exported identities unchanged. Do not rewrite a report's image version to reuse it on a different image. Files over 64 MiB are rejected.

The supplied CS2 analysis has one entry for every inventory item. It documents functional relationships and uncertainty, not verified transitive dependencies. The source JSON lacks manifests, service dependency values, hardware IDs and runtime traces. Component-store names may be abbreviated. Unknown entries are intentionally marked Review.
