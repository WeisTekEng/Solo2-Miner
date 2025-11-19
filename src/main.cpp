#include <Arduino.h>
#include <ArduinoJson.h>
#include <M5Core2.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "mbedtls/md.h"
#include "configs.h"

// Global statistics
volatile long templates = 0;
volatile long hashes = 0;
volatile int halfshares = 0;
volatile int shares = 0;
volatile int valids = 0;
volatile bool blockFound = false;
volatile unsigned long blockFoundTime = 0;

// Cached data for display (updated by background task)
String btcBalance = "...";
float btcPrice = 0;

// Display mode: 0 = Performance (simple), 1 = Detailed (fancy)
volatile int displayMode = 0;

// Mutex for thread-safe statistics updates
SemaphoreHandle_t statsMutex;

// Inline functions for speed
inline bool checkHalfShare(unsigned char* hash) {
  // Check last 2 bytes for zeros (16 bits)
  return (*(uint16_t*)(hash + 30) == 0);
}

inline bool checkShare(unsigned char* hash) {
  // Check last 4 bytes for zeros (32 bits)
  return (*(uint32_t*)(hash + 28) == 0);
}

inline bool checkValid(unsigned char* hash, unsigned char* target) {
  // Compare 32-bit chunks for speed
  uint32_t* h = (uint32_t*)hash;
  uint32_t* t = (uint32_t*)target;
  
  for(int8_t i = 7; i >= 0; i--) {
    if(h[i] > t[i]) return false;
    if(h[i] < t[i]) return true;
  }
  return true;
}

inline uint8_t hex(char ch) {
    return (ch > 57) ? (ch - 55) : (ch - 48);
}

int to_byte_array(const char *in, size_t in_size, uint8_t *out) {
    int count = 0;
    if (in_size % 2) {
        while (*in && out) {
            *out = hex(*in++);
            if (!*in) return count;
            *out = (*out << 4) | hex(*in++);
            *out++;
            count++;
        }
    } else {
        while (*in && out) {
            *out++ = (hex(*in++) << 4) | hex(*in++);
            count++;
        }
    }
    return count;
}

void runWorker(void *name) {
  Serial.printf("\nRunning %s on core %d\n", (char *)name, xPortGetCoreID());
  
  // Set CPU frequency to maximum
  setCpuFrequencyMhz(240);
  
  // Allocate buffers once
  byte interResult[32] __attribute__((aligned(4)));
  byte shaResult[32] __attribute__((aligned(4)));
  
  while(true) { 
    WiFiClient client;
    client.setTimeout(10000);
    client.setNoDelay(true); // Disable Nagle's algorithm
    
    Serial.printf("%s: Connecting to %s:%d\n", (char*)name, POOL_URL, POOL_PORT);
    if (!client.connect(POOL_URL, POOL_PORT)) {
      Serial.printf("%s: Connection failed!\n", (char*)name);
      delay(5000);
      continue;
    }
    Serial.printf("%s: Connected!\n", (char*)name);

    xSemaphoreTake(statsMutex, portMAX_DELAY);
    templates++;
    xSemaphoreGive(statsMutex);
    
    DynamicJsonDocument doc(4096);
    String payload;
    String line;
    
    // Mining subscribe
    payload = "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n";
    Serial.printf("%s: Sending subscribe\n", (char*)name);
    client.print(payload);
    line = client.readStringUntil('\n');
    Serial.printf("%s: Received: %s\n", (char*)name, line.c_str());
    
    if (deserializeJson(doc, line)) {
      Serial.printf("%s: JSON parse error on subscribe\n", (char*)name);
      client.stop();
      delay(5000);
      continue;
    }
    
    String sub_details = String((const char*) doc["result"][0][0][1]);
    String extranonce1 = String((const char*) doc["result"][1]);
    int extranonce2_size = doc["result"][2];
    
    Serial.printf("%s: extranonce1=%s, extranonce2_size=%d\n", (char*)name, extranonce1.c_str(), extranonce2_size);
    
    line = client.readStringUntil('\n');
    Serial.printf("%s: Received difficulty: %s\n", (char*)name, line.c_str());
    deserializeJson(doc, line);

    // Authorize
    payload = "{\"params\":[\"" + String(ADDRESS) + "\",\"password\"],\"id\":2,\"method\":\"mining.authorize\"}\n";
    Serial.printf("%s: Sending authorize\n", (char*)name);
    client.print(payload);
    line = client.readStringUntil('\n');
    Serial.printf("%s: Auth response: %s\n", (char*)name, line.c_str());
    deserializeJson(doc, line);
    
    String job_id = String((const char*) doc["params"][0]);
    String prevhash = String((const char*) doc["params"][1]);
    String coinb1 = String((const char*) doc["params"][2]);
    String coinb2 = String((const char*) doc["params"][3]);
    JsonArray merkle_branch = doc["params"][4];
    String version = String((const char*) doc["params"][5]);
    String nbits = String((const char*) doc["params"][6]);
    String ntime = String((const char*) doc["params"][7]);
    
    Serial.printf("%s: Job ID=%s, nbits=%s\n", (char*)name, job_id.c_str(), nbits.c_str());
    
    // Read remaining responses without parsing
    line = client.readStringUntil('\n');
    Serial.printf("%s: Extra line: %s\n", (char*)name, line.c_str());
    line = client.readStringUntil('\n');
    Serial.printf("%s: Extra line: %s\n", (char*)name, line.c_str());

    // Calculate target
    String target = nbits.substring(2);
    int zeros = (int) strtol(nbits.substring(0, 2).c_str(), 0, 16) - 3;
    for (int k = 0; k < zeros; k++) target += "00";
    while(target.length() < 64) target = "0" + target;
    
    Serial.printf("%s: Target: %s\n", (char*)name, target.c_str());
    Serial.printf("%s: Starting mining...\n", (char*)name);
    
    uint8_t bytearray_target[32] __attribute__((aligned(4)));
    to_byte_array(target.c_str(), 64, bytearray_target);
    
    // Reverse target bytes
    for (size_t j = 0; j < 16; j++) {
        uint8_t tmp = bytearray_target[j];
        bytearray_target[j] = bytearray_target[31 - j];
        bytearray_target[31 - j] = tmp;
    }

    // Generate extranonce2
    uint32_t extranonce2_a = esp_random();
    uint32_t extranonce2_b = esp_random();
    char extranonce2[17];
    snprintf(extranonce2, sizeof(extranonce2), "%08x%08x", extranonce2_a, extranonce2_b);

    // Build coinbase
    String coinbase = coinb1 + extranonce1 + String(extranonce2) + coinb2;
    size_t str_len = coinbase.length() / 2;
    uint8_t* bytearray_coinbase = (uint8_t*)malloc(str_len);
    to_byte_array(coinbase.c_str(), str_len * 2, bytearray_coinbase);

    // Setup SHA256 context once
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);

    // Double SHA256 of coinbase
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, bytearray_coinbase, str_len);
    mbedtls_md_finish(&ctx, interResult);

    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, interResult, 32);
    mbedtls_md_finish(&ctx, shaResult);

    free(bytearray_coinbase);

    // Calculate merkle root
    byte merkle_result[32] __attribute__((aligned(4)));
    memcpy(merkle_result, shaResult, 32);
    
    byte merkle_concatenated[64] __attribute__((aligned(4)));
    for (size_t k = 0; k < merkle_branch.size(); k++) {
        const char* merkle_element = (const char*) merkle_branch[k];
        uint8_t bytearray_merkle[32];
        to_byte_array(merkle_element, 64, bytearray_merkle);

        memcpy(merkle_concatenated, merkle_result, 32);
        memcpy(merkle_concatenated + 32, bytearray_merkle, 32);
            
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, merkle_concatenated, 64);
        mbedtls_md_finish(&ctx, interResult);

        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, interResult, 32);
        mbedtls_md_finish(&ctx, merkle_result);
    }
    
    // Build merkle root string
    char merkle_root[65];
    for (int i = 0; i < 32; i++) {
      snprintf(merkle_root + (i * 2), 3, "%02x", merkle_result[i]);
    }

    // Build and prepare block header
    String blockheader = version + prevhash + String(merkle_root) + nbits + ntime + "00000000";
    uint8_t bytearray_blockheader[80] __attribute__((aligned(4)));
    to_byte_array(blockheader.c_str(), 160, bytearray_blockheader);
    
    // Reverse version (bytes 0-3)
    for (size_t j = 0; j < 2; j++) {
        uint8_t tmp = bytearray_blockheader[j];
        bytearray_blockheader[j] = bytearray_blockheader[3 - j];
        bytearray_blockheader[3 - j] = tmp;
    }
    
    // Reverse merkle (bytes 36-67)
    for (size_t j = 0; j < 16; j++) {
        uint8_t tmp = bytearray_blockheader[36 + j];
        bytearray_blockheader[36 + j] = bytearray_blockheader[67 - j];
        bytearray_blockheader[67 - j] = tmp;
    }
    
    // Reverse difficulty (bytes 72-75)
    for (size_t j = 0; j < 2; j++) {
        uint8_t tmp = bytearray_blockheader[72 + j];
        bytearray_blockheader[72 + j] = bytearray_blockheader[75 - j];
        bytearray_blockheader[75 - j] = tmp;
    }

    // Mine - unroll loop for speed
    uint32_t nonce = 0;
    const uint32_t BATCH_SIZE = 1000;
    const uint32_t REPORT_INTERVAL = 100000; // Report every 100k hashes
    uint32_t local_hashes = 0;
    
    Serial.printf("%s: Mining started, target difficulty\n", (char*)name);
    
    while(nonce < MAX_NONCE) {
      // Process BATCH_SIZE nonces before checking stats
      for(uint32_t i = 0; i < BATCH_SIZE && nonce < MAX_NONCE; i++, nonce++) {
        // Update nonce in header
        bytearray_blockheader[76] = nonce & 0xFF;
        bytearray_blockheader[77] = (nonce >> 8) & 0xFF;
        bytearray_blockheader[78] = (nonce >> 16) & 0xFF;
        bytearray_blockheader[79] = (nonce >> 24) & 0xFF;

        // Double SHA256
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, bytearray_blockheader, 80);
        mbedtls_md_finish(&ctx, interResult);

        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, interResult, 32);
        mbedtls_md_finish(&ctx, shaResult);

        local_hashes++;

        // Quick checks using optimized functions
        if(checkHalfShare(shaResult)) {
          xSemaphoreTake(statsMutex, portMAX_DELAY);
          halfshares++;
          xSemaphoreGive(statsMutex);
          
          if(checkShare(shaResult)) {
            xSemaphoreTake(statsMutex, portMAX_DELAY);
            shares++;
            xSemaphoreGive(statsMutex);
          }
        }
        
        // Check if valid
        if(checkValid(shaResult, bytearray_target)) {
          Serial.println("\n\n========================================");
          Serial.println("    VALID BLOCK FOUND!!!");
          Serial.println("========================================");
          Serial.printf("Worker: %s on core %d\n", (char*)name, xPortGetCoreID());
          Serial.printf("Nonce: %u (0x%08x)\n", nonce, nonce);
          Serial.printf("Job ID: %s\n", job_id.c_str());
          Serial.print("Block hash: ");
          for (size_t i = 0; i < 32; i++) Serial.printf("%02x", shaResult[31-i]);
          Serial.println();
          Serial.println("========================================\n");
          
          xSemaphoreTake(statsMutex, portMAX_DELAY);
          valids++;
          blockFound = true;
          blockFoundTime = millis();
          xSemaphoreGive(statsMutex);
          
          char nonceHex[9];
          snprintf(nonceHex, 9, "%08x", nonce);
          payload = "{\"params\":[\"" + String(ADDRESS) + "\",\"" + job_id + 
                    "\",\"" + String(extranonce2) + "\",\"" + ntime + 
                    "\",\"" + String(nonceHex) + "\"],\"id\":1,\"method\":\"mining.submit\"}\n";
          Serial.print("Submitting to pool: "); Serial.println(payload);
          client.print(payload);
          line = client.readStringUntil('\n');
          Serial.print("Pool response: "); Serial.println(line);
          
          // Flash screen
          for(int flash = 0; flash < 5; flash++) {
            M5.Lcd.fillScreen(GREEN);
            delay(200);
            M5.Lcd.fillScreen(BLACK);
            delay(200);
          }
          
          nonce = MAX_NONCE; // Exit mining loop
          break;
        }
      }
      
      // Update global hash counter in batches
      xSemaphoreTake(statsMutex, portMAX_DELAY);
      hashes += local_hashes;
      xSemaphoreGive(statsMutex);
      
      // Progress report
      if (nonce % REPORT_INTERVAL == 0 && nonce > 0) {
        Serial.printf("%s: %u hashes done (%.2f%%)\n", (char*)name, nonce, (nonce * 100.0) / MAX_NONCE);
        // Very brief yield
        taskYIELD();
      }
      
      local_hashes = 0;
    }
    
    // Update any remaining hashes
    if (local_hashes > 0) {
      xSemaphoreTake(statsMutex, portMAX_DELAY);
      hashes += local_hashes;
      xSemaphoreGive(statsMutex);
    }
    
    Serial.printf("%s: Finished mining job, getting new job...\n", (char*)name);
    
    mbedtls_md_free(&ctx);
    client.stop();
  }
}

void runBackgroundTasks(void *name) {
  Serial.println("Background task started");
  vTaskDelay(10000 / portTICK_PERIOD_MS); // Wait 10s before first check
  
  while(1) {
    // Check BTC price every 5 minutes
    Serial.println("Fetching BTC price...");
    WiFiClientSecure client;
    client.setInsecure();
    if (client.connect("api.coinbase.com", 443)) {
      client.print("GET /v2/prices/BTC-USD/spot HTTP/1.1\r\n"
                  "Host: api.coinbase.com\r\n"
                  "Connection: close\r\n\r\n");
      String response = "";
      while (client.connected() || client.available()) {
        if (client.available()) {
          response += (char)client.read();
        }
      }
      int jsonStart = response.indexOf("{");
      if (jsonStart > 0) {
        String jsonStr = response.substring(jsonStart);
        DynamicJsonDocument doc(1024);
        if (!deserializeJson(doc, jsonStr)) {
          btcPrice = doc["data"]["amount"].as<float>();
          Serial.printf("BTC Price: $%.2f\n", btcPrice);
        }
      }
      client.stop();
    }
    
    vTaskDelay(60000 / portTICK_PERIOD_MS); // Wait 1 minute
    
    // Check balance
    Serial.println("Fetching balance...");
    client.setInsecure();
    if (client.connect("blockchain.info", 443)) {
      String addr = String(ADDRESS);
      client.print("GET /q/addressbalance/" + addr + " HTTP/1.1\r\n"
                  "Host: blockchain.info\r\n"
                  "Connection: close\r\n\r\n");
      String response = "";
      while (client.connected() || client.available()) {
        if (client.available()) {
          response += (char)client.read();
        }
      }
      int bodyStart = response.indexOf("\r\n\r\n");
      if (bodyStart > 0) {
        String body = response.substring(bodyStart + 4);
        body.trim();
        long satoshis = body.toInt();
        float btc = satoshis / 100000000.0;
        if (btc > 0) {
          btcBalance = String(btc, 8) + " BTC";
        } else {
          btcBalance = "0 BTC";
        }
        Serial.printf("Balance: %s\n", btcBalance.c_str());
      }
      client.stop();
    }
    
    // Wait 4 minutes before next cycle (5 min total)
    vTaskDelay(240000 / portTICK_PERIOD_MS);
  }
}

void runMonitor(void *name) {
  unsigned long start = millis();
  unsigned long lastUpdate = 0;
  
  Serial.println("Monitor task started");
  
  while (1) {
    unsigned long now = millis();
    
    // Check for button press to toggle display mode
    M5.update();
    if (M5.BtnA.wasPressed()) {
      displayMode = (displayMode + 1) % 2;
      Serial.printf("Display mode changed to: %s\n", displayMode == 0 ? "Performance" : "Detailed");
      lastUpdate = 0; // Force immediate update
    }
    
    // Update interval depends on mode
    int updateInterval = (displayMode == 0) ? 5000 : 3000;
    
    // Only update display based on mode
    if (now - lastUpdate < updateInterval) {
      vTaskDelay(500 / portTICK_PERIOD_MS);
      continue;
    }
    lastUpdate = now;
    unsigned long elapsed = now - start;
    
    xSemaphoreTake(statsMutex, portMAX_DELAY);
    long local_hashes = hashes;
    long local_templates = templates;
    int local_halfshares = halfshares;
    int local_shares = shares;
    int local_valids = valids;
    bool local_blockFound = blockFound;
    unsigned long local_blockTime = blockFoundTime;
    xSemaphoreGive(statsMutex);
    
    float hashrate = (elapsed > 0) ? (1.0 * local_hashes) / elapsed : 0.0;
    
    // BLOCK FOUND CELEBRATION! (always show regardless of mode)
    if (local_blockFound && (now - local_blockTime < 60000)) {
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.setTextSize(3);
      M5.Lcd.setCursor(20, 60);
      M5.Lcd.println("BLOCK FOUND!");
      M5.Lcd.setTextSize(2);
      M5.Lcd.setCursor(40, 100);
      M5.Lcd.println("YOU WIN!");
      M5.Lcd.setTextSize(1);
      M5.Lcd.setTextColor(YELLOW);
      M5.Lcd.setCursor(10, 140);
      M5.Lcd.printf("Valid blocks: %d", local_valids);
      M5.Lcd.setCursor(10, 160);
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.println("Check your wallet!");
      M5.Lcd.setCursor(10, 180);
      M5.Lcd.printf("%.2f BTC reward!", 3.125);
      vTaskDelay(5000 / portTICK_PERIOD_MS);
      continue;
    }
    
    M5.Lcd.fillScreen(BLACK);
    
    // ========== PERFORMANCE MODE (Simple & Fast) ==========
    if (displayMode == 0) {
      M5.Lcd.setTextSize(1);
      M5.Lcd.setTextColor(WHITE);
      
      int y = 5;
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("Solo2 Miner [Performance Mode]");
      y += 15;
      
      M5.Lcd.drawLine(0, y, 320, y, GREEN);
      y += 5;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.printf("%.2f KH/s", hashrate);
      y += 15;
      
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("Runtime: %ldm %lds", elapsed/60000, (elapsed/1000)%60);
      y += 15;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("Hashes: %.2fM", local_hashes/1000000.0);
      y += 15;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.setTextColor(YELLOW);
      M5.Lcd.printf("Templates: %ld", local_templates);
      y += 15;
      
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("Shares: 16bit=%d 32bit=%d", local_halfshares, local_shares);
      y += 15;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.setTextColor(local_valids > 0 ? GREEN : RED);
      M5.Lcd.printf("Valid blocks: %d", local_valids);
      y += 20;
      
      M5.Lcd.drawLine(0, y, 320, y, GREEN);
      y += 5;
      
      M5.Lcd.setTextColor(CYAN);
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("Pool: %s:%d", POOL_URL, POOL_PORT);
      y += 15;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.print("IP: ");
      M5.Lcd.print(WiFi.localIP());
      y += 15;
      
      if (btcBalance != "...") {
        M5.Lcd.setTextColor(YELLOW);
        M5.Lcd.setCursor(5, y);
        M5.Lcd.printf("Balance: %s", btcBalance.c_str());
        y += 15;
      }
      
      if (btcPrice > 0) {
        M5.Lcd.setTextColor(GREEN);
        M5.Lcd.setCursor(5, y);
        M5.Lcd.printf("BTC Price: $%.0f", btcPrice);
        y += 15;
      }
      
      // Button hint
      M5.Lcd.setTextColor(DARKGREY);
      M5.Lcd.setCursor(5, 220);
      M5.Lcd.printf("Press Button A for Detailed Mode");
    }
    
    // ========== DETAILED MODE (Fancy with all features) ==========
    else {
      // Draw WiFi signal strength indicator (top right)
      int rssi = WiFi.RSSI();
      int bars = 0;
      if (rssi > -55) bars = 4;
      else if (rssi > -65) bars = 3;
      else if (rssi > -75) bars = 2;
      else if (rssi > -85) bars = 1;
      
      uint16_t wifiColor = (bars > 2) ? GREEN : (bars > 1) ? YELLOW : RED;
      int wifiX = 290;
      int wifiY = 5;
      
      for (int i = 0; i < 4; i++) {
        if (i < bars) {
          M5.Lcd.fillRect(wifiX + (i * 6), wifiY + (12 - (i * 3)), 4, i * 3 + 3, wifiColor);
        } else {
          M5.Lcd.drawRect(wifiX + (i * 6), wifiY + (12 - (i * 3)), 4, i * 3 + 3, DARKGREY);
        }
      }
      
          // Show signal strength as dBm (small text)
    M5.Lcd.setTextSize(1);
    M5.Lcd.setTextColor(wifiColor);
    M5.Lcd.setCursor(255, 14);
    M5.Lcd.printf("%ddB", rssi);
    
    M5.Lcd.setTextColor(WHITE);
    M5.Lcd.setTextSize(2);
    
    // Title - smaller to save space
    M5.Lcd.setCursor(5, 5);
    M5.Lcd.println("Solo2 Miner");
    int headerWidth = M5.Lcd.textWidth("Solo2 Miner");
    int headerHeight = 16;
    
    // Show temperature if available
    M5.Lcd.setTextSize(1);
    M5.Lcd.setTextColor(CYAN);
    M5.Lcd.setCursor(200, 14);
    float temp = temperatureRead();
    if (temp > 70) M5.Lcd.setTextColor(RED);
    else if (temp > 60) M5.Lcd.setTextColor(YELLOW);
    else M5.Lcd.setTextColor(CYAN);
    M5.Lcd.printf("Cpu: %.0fC", temp);
      
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.drawLine(0, 28, 320, 28, GREEN);
      
      // Progress bar
      int progress = min(100, (int)((hashrate / 25.0) * 100));
      M5.Lcd.drawRect(5, 33, 310, 15, WHITE);
      M5.Lcd.fillRect(7, 35, 306 * progress / 100, 11, GREEN);
      
      M5.Lcd.setTextSize(1);
      M5.Lcd.setTextColor(DARKGREY);
      M5.Lcd.setCursor(270, 37);
      M5.Lcd.printf("%d%%", progress);
      
      M5.Lcd.setTextColor(WHITE);
      int y = 55;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("Hashrate: %.2f KH/s", hashrate);
      
      // Power efficiency
      M5.Lcd.setTextColor(DARKGREY);
      M5.Lcd.setCursor(200, y);
      if (hashrate > 0) {
        M5.Lcd.printf("%.0f H/J", (hashrate * 1000) / 0.5);
      }
      M5.Lcd.setTextColor(WHITE);
      y += 16;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("Runtime: %ldm %lds", elapsed/60000, (elapsed/1000)%60);
      y += 16;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("Hashes: %.2fM", local_hashes/1000000.0);
      
      // Average hash time
      if (local_hashes > 0 && elapsed > 0) {
        float usPerHash = (elapsed * 1000.0) / local_hashes;
        M5.Lcd.setTextColor(DARKGREY);
        M5.Lcd.setCursor(200, y);
        M5.Lcd.printf("%.1fus", usPerHash);
        M5.Lcd.setTextColor(WHITE);
      }
      y += 16;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.setTextColor(YELLOW);
      M5.Lcd.printf("Templates: %ld", local_templates);
      
      // Battery percentage
      M5.Lcd.setTextColor(DARKGREY);
      M5.Lcd.setCursor(200, y);
      int battLevel = M5.Axp.GetBatteryLevel();
      bool charging = M5.Axp.isCharging();
      if (charging) {
        M5.Lcd.setTextColor(GREEN);
        M5.Lcd.printf("CHG %d%%", battLevel);
      } else if (battLevel > 50) {
        M5.Lcd.setTextColor(GREEN);
        M5.Lcd.printf("BAT %d%%", battLevel);
      } else if (battLevel > 20) {
        M5.Lcd.setTextColor(YELLOW);
        M5.Lcd.printf("BAT %d%%", battLevel);
      } else {
        M5.Lcd.setTextColor(RED);
        M5.Lcd.printf("BAT %d%%", battLevel);
      }
      M5.Lcd.setTextColor(WHITE);
      y += 16;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("16bit: %d | 32bit: %d", local_halfshares, local_shares);
      y += 16;
      
      M5.Lcd.setCursor(5, y);
      M5.Lcd.setTextColor(local_valids > 0 ? GREEN : RED);
      M5.Lcd.printf("Valid: %d", local_valids);
      y += 18;
      
      M5.Lcd.drawLine(0, y, 320, y, GREEN);
      y += 6;
      
      // Balance
      M5.Lcd.setTextColor(YELLOW);
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("Bal: %s", btcBalance.c_str());
      y += 16;
      
      // BTC price
      if (btcPrice > 0) {
        M5.Lcd.setTextColor(GREEN);
        M5.Lcd.setCursor(5, y);
        M5.Lcd.printf("BTC: $%.0f", btcPrice);
        y += 16;
      }
      
      M5.Lcd.setTextColor(CYAN);
      M5.Lcd.setCursor(5, y);
      M5.Lcd.printf("%s:%d", POOL_URL, POOL_PORT);
      
      // Button hint
      M5.Lcd.setTextColor(DARKGREY);
      M5.Lcd.setCursor(5, 220);
      M5.Lcd.printf("Press Button A for Performance");
    }
    
    Serial.printf("Monitor: Display updated (Mode: %d)\n", displayMode);
  }
}

void setup(){
  M5.begin(true, true, true, true);
  
  Serial.begin(115200);
  delay(100);

  // CPU optimizations
  setCpuFrequencyMhz(240); // Max frequency
  
  // Create mutex
  statsMutex = xSemaphoreCreateMutex();

  // Disable watchdog
  disableCore0WDT();
  disableCore1WDT();
  
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextColor(WHITE);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(10, 10);
  M5.Lcd.println("Solo2 Miner");
  M5.Lcd.drawLine(0, 35, 320, 35, GREEN);
  
  M5.Lcd.setTextSize(1);
  M5.Lcd.setCursor(10, 50);
  M5.Lcd.println("Optimized for maximum speed");
  M5.Lcd.setCursor(10, 70);
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.println("CPU: 240MHz | Dual Core");
  
  M5.Lcd.setTextColor(WHITE);
  M5.Lcd.setCursor(10, 100);
  M5.Lcd.println("Connecting WiFi...");
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    M5.Lcd.print(".");
    attempts++;
  }
  
  if (WiFi.status() != WL_CONNECTED) {
    M5.Lcd.setCursor(10, 130);
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println("WiFi FAILED!");
    while(1) delay(1000);
  }
  
  M5.Lcd.setCursor(10, 130);
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.println("Connected!");
  M5.Lcd.setTextColor(CYAN);
  M5.Lcd.setCursor(10, 150);
  M5.Lcd.print("IP: ");
  M5.Lcd.println(WiFi.localIP());
  M5.Lcd.setCursor(10, 170);
  M5.Lcd.printf("Pool: %s:%d", POOL_URL, POOL_PORT);
  
  delay(2000);

  // Start background task for API calls (lowest priority, core 1)
  xTaskCreatePinnedToCore(runBackgroundTasks, "Background", 8000, NULL, 0, NULL, 1);
  Serial.println("Background task created");
  
  // Start workers - use both cores with priority 1
  for (size_t i = 0; i < THREADS; i++) {
    char *name = (char*) malloc(32);
    sprintf(name, "Worker[%d]", i);
    
    // Pin to specific core for better performance
    // Priority 1 (higher than background)
    BaseType_t core = (i % 2);
    xTaskCreatePinnedToCore(runWorker, name, 35000, (void*)name, 1, NULL, core);
    Serial.printf("Starting %s on core %d\n", name, core);
  }

  // Monitor on core 1 with priority 2 (higher than workers)
  xTaskCreatePinnedToCore(runMonitor, "Monitor", 8000, NULL, 2, NULL, 1);
  Serial.println("Monitor task created with priority 2");
}

void loop(){
  delay(10000);
}