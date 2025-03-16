using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using Microsoft.Identity.Client;

public static class TokenCacheHelper
{
    // Configurable parameters
    private static string _cacheDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MSAL.PS");
    private static string _cacheFileName = "MSAL.PS.msalcache.bin3";
    private static bool _encryptCache = true;
    private static int _backupCount = 0;
    private static string _partitionKey = null;
    private static bool _useMacKeychain = false;

    /// <summary>
    /// Path to the token cache
    /// </summary>
    public static string CacheFilePath => Path.Combine(_cacheDirectory, _cacheFileName);

    /// <summary>
    /// Set the directory where the token cache file will be stored
    /// </summary>
    public static void SetCacheDirectory(string directory)
    {
        if (!string.IsNullOrWhiteSpace(directory))
        {
            _cacheDirectory = directory;
        }
    }

    /// <summary>
    /// Set the name of the token cache file
    /// </summary>
    public static void SetCacheFileName(string fileName)
    {
        if (!string.IsNullOrWhiteSpace(fileName))
        {
            _cacheFileName = fileName;
        }
    }

    /// <summary>
    /// Disable encryption of the token cache
    /// </summary>
    public static void DisableEncryption()
    {
        _encryptCache = false;
    }

    /// <summary>
    /// Set the number of backup files to maintain
    /// </summary>
    public static void SetBackupCount(int count)
    {
        if (count >= 0)
        {
            _backupCount = count;
        }
    }

    /// <summary>
    /// Set a custom partition key for the token cache
    /// </summary>
    public static void SetPartitionKey(string key)
    {
        _partitionKey = key;
    }

    /// <summary>
    /// Enable Mac-style keychain partitioning
    /// </summary>
    public static void EnableMacKeychain()
    {
        _useMacKeychain = true;
    }

    /// <summary>
    /// Set up token cache serialization
    /// </summary>
    public static void EnableSerialization(ITokenCache tokenCache)
    {
        tokenCache.SetBeforeAccessAsync(async args =>
        {
            // Apply partition key if specified
            if (!string.IsNullOrEmpty(_partitionKey))
            {
                args.SuggestedCacheKey = _partitionKey;
            }

            byte[] cacheData = null;
            if (File.Exists(CacheFilePath))
            {
                try
                {
                    byte[] fileData = File.ReadAllBytes(CacheFilePath);
                    
                    // Decrypt data if encryption is enabled
                    cacheData = _encryptCache 
                        ? ProtectedData.Unprotect(fileData, null, DataProtectionScope.CurrentUser)
                        : fileData;
                }
                catch (Exception ex)
                {
                    // If we can't read the cache, just start fresh
                    Console.WriteLine($"Token cache read error: {ex.Message}");
                }
            }

            args.TokenCache.DeserializeMsalV3(cacheData);
        });

        tokenCache.SetAfterAccessAsync(async args =>
        {
            // Apply partition key if specified
            if (!string.IsNullOrEmpty(_partitionKey))
            {
                args.SuggestedCacheKey = _partitionKey;
            }

            // If the cache has changed, persist it
            if (args.HasStateChanged)
            {
                try
                {
                    // Ensure the cache directory exists
                    Directory.CreateDirectory(_cacheDirectory);

                    // Create backups if enabled
                    if (_backupCount > 0)
                    {
                        CreateBackup();
                    }

                    // Serialize the cache
                    byte[] cacheData = args.TokenCache.SerializeMsalV3();
                    
                    // Encrypt if enabled
                    byte[] fileData = _encryptCache
                        ? ProtectedData.Protect(cacheData, null, DataProtectionScope.CurrentUser)
                        : cacheData;

                    // Write to disk
                    File.WriteAllBytes(CacheFilePath, fileData);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Token cache write error: {ex.Message}");
                }
            }
        });

        // Also set the sync versions for compatibility
        tokenCache.SetBeforeAccess(BeforeAccessNotification);
        tokenCache.SetAfterAccess(AfterAccessNotification);
    }

    private static readonly object FileLock = new object();

    private static void BeforeAccessNotification(TokenCacheNotificationArgs args)
    {
        lock (FileLock)
        {
            // Apply partition key if specified
            if (!string.IsNullOrEmpty(_partitionKey))
            {
                args.SuggestedCacheKey = _partitionKey;
            }

            byte[] cacheData = null;
            
            if (File.Exists(CacheFilePath))
            {
                try
                {
                    byte[] fileData = File.ReadAllBytes(CacheFilePath);
                    
                    // Decrypt data if encryption is enabled
                    cacheData = _encryptCache 
                        ? ProtectedData.Unprotect(fileData, null, DataProtectionScope.CurrentUser)
                        : fileData;
                }
                catch
                {
                    // If we can't read the cache, just start fresh
                }
            }

            args.TokenCache.DeserializeMsalV3(cacheData);
        }
    }

    private static void AfterAccessNotification(TokenCacheNotificationArgs args)
    {
        // If the cache has changed, persist it
        if (args.HasStateChanged)
        {
            lock (FileLock)
            {
                try
                {
                    // Apply partition key if specified
                    if (!string.IsNullOrEmpty(_partitionKey))
                    {
                        args.SuggestedCacheKey = _partitionKey;
                    }

                    // Ensure the cache directory exists
                    Directory.CreateDirectory(_cacheDirectory);

                    // Create backups if enabled
                    if (_backupCount > 0)
                    {
                        CreateBackup();
                    }

                    // Serialize the cache
                    byte[] cacheData = args.TokenCache.SerializeMsalV3();
                    
                    // Encrypt if enabled
                    byte[] fileData = _encryptCache
                        ? ProtectedData.Protect(cacheData, null, DataProtectionScope.CurrentUser)
                        : cacheData;

                    // Write to disk
                    File.WriteAllBytes(CacheFilePath, fileData);
                }
                catch
                {
                    // If we can't write the cache, just continue
                }
            }
        }
    }

    /// <summary>
    /// Create a backup of the token cache file
    /// </summary>
    private static void CreateBackup()
    {
        if (!File.Exists(CacheFilePath))
            return;

        try
        {
            // Create backup name with timestamp
            string timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            string backupDir = Path.Combine(_cacheDirectory, "Backup");
            Directory.CreateDirectory(backupDir);
            
            string backupFileName = Path.GetFileNameWithoutExtension(_cacheFileName) + 
                                    $".{timestamp}" + 
                                    Path.GetExtension(_cacheFileName);
            
            string backupPath = Path.Combine(backupDir, backupFileName);
            
            // Create the backup
            File.Copy(CacheFilePath, backupPath, true);
            
            // Clean up old backups if we exceed the limit
            if (_backupCount > 0)
            {
                string[] backupFiles = Directory.GetFiles(backupDir, 
                    Path.GetFileNameWithoutExtension(_cacheFileName) + ".*" + Path.GetExtension(_cacheFileName));
                
                // Sort by filename (which includes the timestamp) to get oldest first
                Array.Sort(backupFiles);
                
                // Remove the oldest backups if we have too many
                if (backupFiles.Length > _backupCount)
                {
                    for (int i = 0; i < backupFiles.Length - _backupCount; i++)
                    {
                        try
                        {
                            File.Delete(backupFiles[i]);
                        }
                        catch
                        {
                            // Ignore errors deleting old backups
                        }
                    }
                }
            }
        }
        catch
        {
            // Ignore backup errors
        }
    }
}