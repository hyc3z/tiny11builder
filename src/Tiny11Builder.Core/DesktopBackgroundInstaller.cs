namespace Tiny11Builder.Core;

public static class DesktopBackgroundInstaller
{
    private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".jpg", ".jpeg", ".png", ".bmp" };

    public static bool IsSupportedExtension(string extension) => SupportedExtensions.Contains(extension);

    public static string ValidateSource(string path)
    {
        var fullPath = PathSafety.Full(path);
        if (!IsSupportedExtension(Path.GetExtension(fullPath)))
            throw new InvalidDataException("Desktop background image must be a JPG, JPEG, PNG or BMP file.");
        PathSafety.RejectReparsePoints(fullPath);
        if (!File.Exists(fullPath)) throw new FileNotFoundException("Desktop background image does not exist.", fullPath);
        return fullPath;
    }

    public static string InstalledWallpaperPath(string sourcePath) =>
        @"C:\Windows\Web\Wallpaper\Tiny11Builder\DesktopBackground" + Path.GetExtension(sourcePath).ToLowerInvariant();

    public static void Apply(string mountDirectory, BuildRecipe recipe, Action<string> log)
    {
        if (string.IsNullOrWhiteSpace(recipe.DesktopBackgroundPath)) return;
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows image mounting is only supported on Windows.");
        ImageOperations.RequireOwnedMount(mountDirectory);
        var source = ValidateSource(recipe.DesktopBackgroundPath);
        var extension = Path.GetExtension(source).ToLowerInvariant();
        var directory = Path.Combine(mountDirectory, "Windows", "Web", "Wallpaper", "Tiny11Builder");
        Directory.CreateDirectory(directory);
        var destination = Path.Combine(directory, "DesktopBackground" + extension);
        File.Copy(source, destination, overwrite: true);
        log($"Desktop background copied into the image: Windows\\Web\\Wallpaper\\Tiny11Builder\\DesktopBackground{extension}");
    }
}
