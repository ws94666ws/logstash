// env2yaml
//
// Merge environment variables into logstash.yml.
// For example, running Docker with:
//
//	docker run -e pipeline.workers=6
//
// or
//
//	docker run -e PIPELINE_WORKERS=6
//
// will cause logstash.yml to contain the line:
//
//	pipeline.workers: 6
package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

var validSettings = []string{
	"api.enabled",
	"api.http.host",
	"api.http.port",
	"api.environment",
	"node.name",
	"path.data",
	"pipeline.id",
	"pipeline.workers",
	"pipeline.output.workers",
	"pipeline.batch.size",
	"pipeline.batch.delay",
	"pipeline.unsafe_shutdown",
	"pipeline.ecs_compatibility",
	"pipeline.ordered",
	"pipeline.plugin_classloaders",
	"pipeline.separate_logs",
	"path.config",
	"config.string",
	"config.test_and_exit",
	"config.reload.automatic",
	"config.reload.interval",
	"config.debug",
	"config.support_escapes",
	"config.field_reference.escape_style",
	"queue.type",
	"path.queue",
	"queue.page_capacity",
	"queue.max_events",
	"queue.max_bytes",
	"queue.checkpoint.acks",
	"queue.checkpoint.writes",
	"queue.checkpoint.interval", // remove it for #17155
	"queue.drain",
	"dead_letter_queue.enable",
	"dead_letter_queue.max_bytes",
	"dead_letter_queue.flush_interval",
	"dead_letter_queue.storage_policy",
	"dead_letter_queue.retain.age",
	"path.dead_letter_queue",
	"log.level",
	"log.format",
	"log.format.json.fix_duplicate_message_fields",
	"metric.collect",
	"path.logs",
	"path.plugins",
	"api.auth.type",
	"api.auth.basic.username",
	"api.auth.basic.password",
	"api.auth.basic.password_policy.mode",
	"api.auth.basic.password_policy.length.minimum",
	"api.auth.basic.password_policy.include.upper",
	"api.auth.basic.password_policy.include.lower",
	"api.auth.basic.password_policy.include.digit",
	"api.auth.basic.password_policy.include.symbol",
	"allow_superuser",
	"monitoring.cluster_uuid",
	"xpack.monitoring.allow_legacy_collection",
	"xpack.monitoring.enabled",
	"xpack.monitoring.collection.interval",
	"xpack.monitoring.elasticsearch.hosts",
	"xpack.monitoring.elasticsearch.username",
	"xpack.monitoring.elasticsearch.password",
	"xpack.monitoring.elasticsearch.proxy",
	"xpack.monitoring.elasticsearch.api_key",
	"xpack.monitoring.elasticsearch.cloud_auth",
	"xpack.monitoring.elasticsearch.cloud_id",
	"xpack.monitoring.elasticsearch.sniffing",
	"xpack.monitoring.elasticsearch.ssl.certificate_authority",
	"xpack.monitoring.elasticsearch.ssl.ca_trusted_fingerprint",
	"xpack.monitoring.elasticsearch.ssl.verification_mode",
	"xpack.monitoring.elasticsearch.ssl.truststore.path",
	"xpack.monitoring.elasticsearch.ssl.truststore.password",
	"xpack.monitoring.elasticsearch.ssl.keystore.path",
	"xpack.monitoring.elasticsearch.ssl.keystore.password",
	"xpack.monitoring.elasticsearch.ssl.certificate",
	"xpack.monitoring.elasticsearch.ssl.key",
	"xpack.monitoring.elasticsearch.ssl.cipher_suites",
	"xpack.management.enabled",
	"xpack.management.logstash.poll_interval",
	"xpack.management.pipeline.id",
	"xpack.management.elasticsearch.hosts",
	"xpack.management.elasticsearch.username",
	"xpack.management.elasticsearch.password",
	"xpack.management.elasticsearch.proxy",
	"xpack.management.elasticsearch.api_key",
	"xpack.management.elasticsearch.cloud_auth",
	"xpack.management.elasticsearch.cloud_id",
	"xpack.management.elasticsearch.sniffing",
	"xpack.management.elasticsearch.ssl.certificate_authority",
	"xpack.management.elasticsearch.ssl.ca_trusted_fingerprint",
	"xpack.management.elasticsearch.ssl.verification_mode",
	"xpack.management.elasticsearch.ssl.truststore.path",
	"xpack.management.elasticsearch.ssl.truststore.password",
	"xpack.management.elasticsearch.ssl.keystore.path",
	"xpack.management.elasticsearch.ssl.keystore.password",
	"xpack.management.elasticsearch.ssl.certificate",
	"xpack.management.elasticsearch.ssl.key",
	"xpack.management.elasticsearch.ssl.cipher_suites",
	"xpack.geoip.download.endpoint",
	"xpack.geoip.downloader.enabled",
}

// Given a setting name, return a downcased version with delimiters removed.
func squashSetting(setting string) string {
	downcased := strings.ToLower(setting)
	de_dotted := strings.Replace(downcased, ".", "", -1)
	de_underscored := strings.Replace(de_dotted, "_", "", -1)
	return de_underscored
}

// Given a setting name like "pipeline.workers" or "PIPELINE_UNSAFE_SHUTDOWN",
// return the canonical setting name. eg. 'pipeline.unsafe_shutdown'
func normalizeSetting(setting string) (string, error) {
	for _, validSetting := range validSettings {
		if squashSetting(setting) == squashSetting(validSetting) {
			return validSetting, nil
		}
	}
	return "", errors.New("Invalid setting: " + setting)
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: env2yaml FILENAME")
	}
	settingsFilePath := os.Args[1]

	settingsFile, err := ioutil.ReadFile(settingsFilePath)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	// Read the original settings file into a map.
	settings := make(map[string]interface{})
	err = yaml.Unmarshal(settingsFile, &settings)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	// Merge any valid settings found in the environment.
	foundNewSettings := false
	for _, line := range os.Environ() {
		kv := strings.SplitN(line, "=", 2)
		key := kv[0]
		setting, err := normalizeSetting(key)
		if err == nil {
			foundNewSettings = true
			log.Printf("Setting '%s' from environment.", setting)
			// we need to keep ${KEY} in the logstash.yml to let Logstash decide using ${KEY}'s value from either keystore or environment
			settings[setting] = fmt.Sprintf("${%s}", key)
		}
	}

	if foundNewSettings {
		output, err := yaml.Marshal(&settings)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		stat, err := os.Stat(settingsFilePath)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		err = ioutil.WriteFile(settingsFilePath, output, stat.Mode())
		if err != nil {
			log.Fatalf("error: %v", err)
		}
	}
}
