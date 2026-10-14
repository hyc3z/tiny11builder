using System.Text.RegularExpressions;

namespace Tiny11Builder.Core;

public static class ImageInventory
{
    public static async Task<IReadOnlyList<ImageInventoryItem>> ReadAsync(DismClient dism, IImageOperations native,
        string mount, CancellationToken token)
    {
        // DISM queries share the same mounted image and log path, so keep them serialized. The native
        // registry and directory scan is independent and can run while DISM is collecting its inventory.
        var nativeItems = Task.Run(() => native.ReadNativeInventory(mount));
        try
        {
            var appText = await dism.RunAsync(token, $"/Image:{mount}", "/Get-ProvisionedAppxPackages").ConfigureAwait(false);
            var featureText = await dism.RunAsync(token, $"/Image:{mount}", "/Get-Features").ConfigureAwait(false);
            var capabilities = await dism.RunAsync(token, $"/Image:{mount}", "/Get-Capabilities").ConfigureAwait(false);
            var packages = await dism.RunAsync(token, $"/Image:{mount}", "/Get-Packages").ConfigureAwait(false);

            var items = new List<ImageInventoryItem>();
            foreach (var app in DismClient.ParseApps(appText))
                items.Add(new(ImageItemKind.ProvisionedApp, app.PackageName, app.DisplayName,
                    !CleanupCatalog.Options.Any(o => CleanupCatalog.MatchesApp(o, app))));
            foreach (var feature in DismClient.ParseFeatures(featureText))
                items.Add(new(ImageItemKind.Feature, feature.Key, feature.Value, true));
            items.AddRange(ParseIdentityStates(capabilities, "Capability Identity", ImageItemKind.Capability));
            items.AddRange(ParseIdentityStates(packages, "Package Identity", ImageItemKind.Package));
            items.AddRange(await nativeItems.ConfigureAwait(false));
            return items.OrderBy(i => i.Kind).ThenBy(i => i.Identity, StringComparer.OrdinalIgnoreCase).ToArray();
        }
        catch
        {
            // The caller discards/unmounts the image on failure. Let the scan finish first so it never
            // reads a mount while cleanup is removing it; preserve the original inventory error.
            try { await nativeItems.ConfigureAwait(false); }
            catch { }
            throw;
        }
    }

    public static IReadOnlyList<ImageInventoryItem> ParseIdentityStates(string text, string field, ImageItemKind kind)
    {
        var items = new List<ImageInventoryItem>();
        string? name = null;
        foreach (var line in text.Split('\n'))
        {
            var identity = Regex.Match(line, $@"^[ \t]*{Regex.Escape(field)}[ \t]*:[ \t]*(.+?)[ \t\r]*$");
            if (identity.Success) name = identity.Groups[1].Value;
            var state = Regex.Match(line, @"^[ \t]*State[ \t]*:[ \t]*(.+?)[ \t\r]*$");
            if (!state.Success || name is null) continue;
            items.Add(new(kind, name, state.Groups[1].Value, true));
            name = null;
        }
        return items;
    }

    public static void ValidateActions(IReadOnlyList<ExpertAction> actions, IReadOnlyList<ImageInventoryItem> items)
    {
        foreach (var action in actions)
            if (!items.Any(i => i.Kind == action.Kind && i.Identity.Equals(action.Identity, StringComparison.Ordinal)))
                throw new InvalidDataException($"The custom action is not in the selected image's current inventory: {action.Kind} / {action.Identity}");
    }
}
