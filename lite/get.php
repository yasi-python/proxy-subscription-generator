<?php

declare(strict_types=1);

/**
 * Stage 2: Config Extractor (Upgraded)
 * - Reads channel data and cached HTML from Stage 1.
 * - Extracts proxy configs from local and remote sources.
 * - NEW: Uses a "Process Once, Use Many" logic for cleaner code.
 * - NEW: Implements a persistent IP cache to speed up runs.
 * - NEW: Generates a summary.json file with run statistics.
 * - Processes, enriches, and saves the final subscription files.
 * - Removes channels from channelsAssets.json if they no longer provide valid configs.
 */

// --- Setup ---
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require 'functions.php';

// --- Configuration Constants ---
const ASSETS_FILE = __DIR__ . '/channelsData/channelsAssets.json';
const HTML_CACHE_DIR = __DIR__ . '/channelsData/html_cache';
const OUTPUT_DIR = __DIR__ . '/subscriptions';
const LOCATION_DIR = OUTPUT_DIR . '/location';
const FINAL_CONFIG_FILE = __DIR__ . '/config.txt';
// NEW: Constant for the persistent IP cache file.
const IP_CACHE_FILE = __DIR__ . "/channelsData/ip_info_cache.json";
// NEW: Constant for the summary file.
const SUMMARY_FILE = OUTPUT_DIR . "/summary.json";

// REFACTORED: Renamed for clarity. This now defines the number of configs to include in the main files.
const CONFIGS_FOR_AGGREGATE = 3; // Process latest 3 configs from each source for final files.
const PRIVATE_CONFIGS_URL = 'https://raw.githubusercontent.com/itsyebekhe/PSGP/main/private_configs.json';


// REFACTORED: The processing logic is now in its own clean function.
/**
 * Processes a single raw config string and enriches it with metadata.
 * @param string $config The raw config string.
 * @param string $source The source channel name.
 * @param int $key The original index of the config.
 * @param array &$ipInfoCache A reference to the IP information cache.
 * @return array|null The enriched config and its metadata, or null if invalid.
 */
function processAndEnrichConfig(
    string $config,
    string $source,
    int $key,
    array &$ipInfoCache
): ?array {
    static $configFields = [
        'vmess' => ['ip' => 'add', 'name' => 'ps'],
        'vless' => ['ip' => 'hostname', 'name' => 'hash'],
        'trojan' => ['ip' => 'hostname', 'name' => 'hash'],
        'tuic' => ['ip' => 'hostname', 'name' => 'hash'],
        'hy2' => ['ip' => 'hostname', 'name' => 'hash'],
        'ss' => ['ip' => 'server_address', 'name' => 'name'],
    ];

    $config = explode('<', $config, 2)[0];
    if (!is_valid($config)) return null;
    
    $type = detect_type($config);
    if ($type === null || !isset($configFields[$type])) return null;
    
    $decodedConfig = configParse($config);
    if ($decodedConfig === null) return null;

    if ($type === 'ss' && (empty($decodedConfig['encryption_method']) || empty($decodedConfig['password']))) return null;

    $ipField = $configFields[$type]['ip'];
    $ipOrHost = $decodedConfig[$ipField] ?? null;
    if ($ipOrHost === null) return null;
    
    // Use the persistent cache
    if (!isset($ipInfoCache[$ipOrHost])) {
        $info = ip_info($ipOrHost);
        $ipInfoCache[$ipOrHost] = $info ? $info->country : 'XX';
    }
    $countryCode = $ipInfoCache[$ipOrHost];

    $flag = ($countryCode === 'XX') ? '❔' : (($countryCode === 'CF') ? '🚩' : getFlags($countryCode));
    $securityEmoji = isEncrypted($config) ? '🔒' : '🔓';
    $newName = sprintf(
        '%s %s | %s %s | @%s [%d]',
        $flag, $countryCode, $securityEmoji, strtoupper($type), $source, $key + 1
    );
    
    $decodedConfig[$configFields[$type]['name']] = $newName;
    $encodedConfig = reparseConfig($decodedConfig, $type);
    if ($encodedConfig === null) return null;

    $finalConfigString = str_replace('amp%3B', '', $encodedConfig);

    return [
        'config' => $finalConfigString,
        'country' => $countryCode,
        'source' => $source,
        'type' => $type, // Return type for stats
    ];
}


// --- 1. Load Source Data ---
echo "--- STAGE 2: CONFIG EXTRACTOR ---" . PHP_EOL;
echo "1. Loading source list from assets file..." . PHP_EOL;
if (!file_exists(ASSETS_FILE)) die("Error: channelsAssets.json not found." . PHP_EOL);
if (!is_dir(HTML_CACHE_DIR)) echo "Warning: HTML cache directory not found." . PHP_EOL;
$sourcesArray = json_decode(file_get_contents(ASSETS_FILE), true);
if (json_last_error() !== JSON_ERROR_NONE) die("Error: Invalid JSON in assets file." . PHP_EOL);

// --- 2. Extract Configs from All Sources ---
echo "\n2. Extracting configs from local and remote sources..." . PHP_EOL;
$configsList = [];
foreach ($sourcesArray as $source => $sourceData) {
    if (isset($sourceData['subscription_url'])) continue;
    $htmlFile = HTML_CACHE_DIR . '/' . $source . '.html';
    if (file_exists($htmlFile)) {
        $htmlContent = file_get_contents($htmlFile);
        if (!empty($htmlContent)) {
            $extractedLinks = extractLinksByType($htmlContent);
            if (!empty($extractedLinks)) {
                $configsList[$source] = array_values(array_unique($extractedLinks));
            }
        }
    }
}
echo "  - HTML extraction complete. Found configs from " . count($configsList) . " sources." . PHP_EOL;

// Integrate private configs
$privateConfigsJson = @file_get_contents(PRIVATE_CONFIGS_URL);
if ($privateConfigsJson !== false) {
    $privateConfigsData = json_decode($privateConfigsJson, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        echo "  - Merging private configs..." . PHP_EOL;
        foreach ($privateConfigsData as $source => $configs) {
            if (empty($configs) || !is_array($configs)) continue;
            $configsList[$source] = isset($configsList[$source])
                ? array_values(array_unique(array_merge($configsList[$source], $configs)))
                : $configs;
        }
    }
}


// REFACTORED: SINGLE PROCESSING BLOCK ("Process Once")
// --- 3. Process All Configs Once and Store in a Master List ---
echo "\n3. Processing all found configs..." . PHP_EOL;

// NEW: Load the persistent IP cache.
$ipInfoCache = file_exists(IP_CACHE_FILE) ? json_decode(file_get_contents(IP_CACHE_FILE), true) : [];

$allProcessedConfigs = [];
$sourcesWithValidConfigs = [];

// NEW: Initialize stats counters for the summary.
$stats = ['protocol_counts' => []];

$totalConfigsToProcess = 0;
foreach ($configsList as $configs) {
    $totalConfigsToProcess += min(count($configs), CONFIGS_FOR_AGGREGATE);
}
$processedCount = 0;

foreach ($configsList as $source => $configs) {
    // We process the number of configs needed for our final files.
    $configsToProcess = array_slice($configs, -CONFIGS_FOR_AGGREGATE);
    $key_offset = count($configs) - count($configsToProcess);

    foreach ($configsToProcess as $key => $config) {
        print_progress(++$processedCount, $totalConfigsToProcess, 'Processing:');
        
        $processedData = processAndEnrichConfig($config, $source, $key + $key_offset, $ipInfoCache);

        if ($processedData !== null) {
            $allProcessedConfigs[] = $processedData;
            $sourcesWithValidConfigs[$source] = true;
            // NEW: Tally protocol counts for stats.
            $protocol = $processedData['type'];
            $stats['protocol_counts'][$protocol] = ($stats['protocol_counts'][$protocol] ?? 0) + 1;
        }
    }
}
echo PHP_EOL . "Processing complete. Found " . count($allProcessedConfigs) . " valid configs in total." . PHP_EOL;


// REFACTORED: GENERATE ALL OUTPUTS FROM THE MASTER LIST ("Use Many")
// --- 4. Write All Subscription Files ---
echo "\n4. Writing all subscription files..." . PHP_EOL;
if (is_dir(OUTPUT_DIR)) deleteFolder(OUTPUT_DIR);
mkdir(LOCATION_DIR . '/normal', 0775, true);
mkdir(LOCATION_DIR . '/base64', 0775, true);

// Prepare final output arrays from the master list
$finalOutput = [];
$locationBased = [];
foreach ($allProcessedConfigs as $procConf) {
    $finalOutput[] = $procConf['config'];
    $locationBased[$procConf['country']][] = $procConf['config'];
}

// Write the files
foreach ($locationBased as $location => $configs) {
    if (empty(trim($location))) continue;
    $plainText = implode(PHP_EOL, $configs);
    file_put_contents(LOCATION_DIR . '/normal/' . $location, $plainText);
    file_put_contents(LOCATION_DIR . '/base64/' . $location, base64_encode($plainText));
}
file_put_contents(FINAL_CONFIG_FILE, implode(PHP_EOL, $finalOutput));
echo "Main and location files written." . PHP_EOL;

// --- 5. Clean up channelsAssets.json ---
echo "\n5. Cleaning up channelsAssets.json..." . PHP_EOL;
$originalSourceCount = count($sourcesArray);
$updatedSourcesArray = array_filter(
    $sourcesArray,
    fn($sourceData, $key) => isset($sourceData['subscription_url']) || isset($sourcesWithValidConfigs[$key]),
    ARRAY_FILTER_USE_BOTH
);
$finalSourceCount = count($updatedSourcesArray);
$removedCount = $originalSourceCount - $finalSourceCount;
if ($removedCount > 0) {
    echo "Removed $removedCount source(s) that had no valid configs." . PHP_EOL;
    file_put_contents(
        ASSETS_FILE,
        json_encode($updatedSourcesArray, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
    );
} else {
    echo "No sources needed to be removed." . PHP_EOL;
}

// --- 6. Save Caches and Generate Summary ---
// NEW: Save the updated IP cache to disk for the next run.
echo "\n6. Saving IP information cache..." . PHP_EOL;
file_put_contents(IP_CACHE_FILE, json_encode($ipInfoCache, JSON_PRETTY_PRINT));

// NEW: Assemble and write the summary file.
echo "\n7. Generating summary file..." . PHP_EOL;
// Get country distribution by directly counting countries from the master list.
$allCountryCodes = array_column($allProcessedConfigs, 'country');
$countryDistribution = array_count_values($allCountryCodes);
arsort($countryDistribution);

$summaryData = [
    'meta' => [
        'last_updated' => date('c'), // ISO 8601 format
    ],
    'sources' => [
        'total_from_assets' => $originalSourceCount,
        'had_configs_extracted' => count($configsList),
        'had_valid_configs' => count($sourcesWithValidConfigs),
        'removed_in_cleanup' => $removedCount,
    ],
    'configs' => [
        'total_valid' => count($allProcessedConfigs),
        'breakdown_by_protocol' => $stats['protocol_counts'],
    ],
    'outputs' => [
        'location_files_created' => count($locationBased),
        'country_distribution' => $countryDistribution,
    ],
];
file_put_contents(SUMMARY_FILE, json_encode($summaryData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

echo "\nDone! All files have been generated successfully." . PHP_EOL;
