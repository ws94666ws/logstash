# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

require 'shellwords'

namespace "artifact" do
  SNAPSHOT_BUILD = ENV["RELEASE"] != "1"
  VERSION_QUALIFIER = ENV["VERSION_QUALIFIER"].to_s.strip.empty? ? nil : ENV["VERSION_QUALIFIER"]
  LOCAL_ARTIFACTS = ENV["LOCAL_ARTIFACTS"] || "true"
  PACKAGE_SUFFIX = SNAPSHOT_BUILD ? "-SNAPSHOT" : ""

  ## TODO: Install new service files
  def package_files
    res = [
      "NOTICE.TXT",
      "CONTRIBUTORS",
      "bin/**/*",
      "config/**/*",
      "data",

      "lib/bootstrap/**/*",
      "lib/pluginmanager/**/*",
      "lib/systeminstall/**/*",
      "lib/secretstore/**/*",

      "logstash-core/lib/**/*",
      "logstash-core/locales/**/*",
      "logstash-core/vendor/**/*",
      "logstash-core/versions-gem-copy.yml",
      "logstash-core/*.gemspec",

      "logstash-core-plugin-api/lib/**/*",
      "logstash-core-plugin-api/versions-gem-copy.yml",
      "logstash-core-plugin-api/*.gemspec",

      "patterns/**/*",
      "vendor/??*/**/*",
      # To include ruby-maven's hidden ".mvn" directory, we need to
      # do add the line below. This directory contains a file called
      # "extensions.xml", which loads the ruby DSL for POMs.
      # Failing to include this file results in updates breaking for
      # plugins which use jar-dependencies.
      # See more in https://github.com/elastic/logstash/issues/4818
      "vendor/??*/**/.mvn/**/*",

      # Without this when JRuby runs 'pleaserun' gem using the AdoptOpenJDK, during the post install script
      # it claims that modules are not open for private introspection and suggest it's missing --add-opens
      # so including these files JRuby run with modules opened to private introspection.
      "vendor/jruby/bin/.jruby.java_opts",
      "vendor/jruby/bin/.jruby.module_opts",
      "Gemfile",
      "Gemfile.lock",
      "x-pack/**/*",
    ]
    if @bundles_jdk
      res += [
        "JDK_VERSION",
        "jdk/**/*",
        "jdk.app/**/*",
      ]
    end
    res
  end

  def default_exclude_paths
    return @exclude_paths if @exclude_paths

    @exclude_paths = []
    @exclude_paths << "**/*.gem"
    @exclude_paths << "**/test/files/slow-xpath.xml"
    @exclude_paths << "**/logstash-*/spec"
    @exclude_paths << "bin/bundle"
    @exclude_paths << "bin/rspec"
    @exclude_paths << "bin/rspec.bat"

    # vendored test/spec artifacts from upstream
    @exclude_paths << 'vendor/**/gems/*/test/**/*'
    @exclude_paths << 'vendor/**/gems/*/spec/**/*'

    # vulnerability scanners shouldn't pick dependency Gemfile(s)
    @exclude_paths << 'vendor/**/gems/**/Gemfile.lock'
    @exclude_paths << 'vendor/**/gems/**/Gemfile'

    @exclude_paths << 'vendor/jruby/lib/ruby/gems/shared/gems/rake-*'
    # exclude ruby-maven-libs 3.3.9 jars until JRuby ships with >= 3.8.9
    @exclude_paths << 'vendor/bundle/jruby/**/gems/ruby-maven-libs-3.3.9/**/*'

    # remove this after JRuby includes rexml 3.3.x
    @exclude_paths << 'vendor/jruby/lib/ruby/gems/shared/gems/rexml-3.2.5/**/*'
    @exclude_paths << 'vendor/jruby/lib/ruby/gems/shared/specifications/rexml-3.2.5.gemspec'

    # remove this after JRuby includes net-imap-0.2.4+
    @exclude_paths << 'vendor/jruby/lib/ruby/gems/shared/specifications/net-imap-0.2.3.gemspec'
    @exclude_paths << 'vendor/jruby/lib/ruby/gems/shared/gems/net-imap-0.2.3/**/*'

    @exclude_paths.freeze
  end

  def oss_exclude_paths
    return @oss_excludes if @oss_excludes
    @oss_excludes = default_exclude_paths + ["x-pack/**/*"]
  end

  def files(exclude_paths = default_exclude_paths)
    Rake::FileList.new(*package_files).exclude(*exclude_paths)
  end

  def source_modified_since?(time, exclude_paths = default_exclude_paths)
    skip_list = ["logstash-core-plugin-api/versions-gem-copy.yml", "logstash-core/versions-gem-copy.yml"]
    result = false
    files(exclude_paths).each do |file|
      next if File.mtime(file) < time || skip_list.include?(file)
      puts "file modified #{file}"
      result = true
      break
    end
    result
  end

  ##
  # @override safe_system([env,] command... [,options])
  # execute Kernel#system call,checking the exit status of the executed command and eventually reporting as exception
  def safe_system(*args)
    command = args.dup # avoid mutating input for reporting
    env = command.size > 1 && command.first.kind_of?(Hash) ? command.shift : {}
    options = command.size > 1 && command.last.kind_of?(Hash) ? command.pop : {}
    fail("unsupported options #{options}") unless options.empty?

    # Normalize command to a single string from either a multi-word string
    # or an array of individual words
    command = command.size > 1 ? Shellwords.join(command.map(&:to_s)) : command.first.to_s

    # prepend the environment
    env.each do |k,v|
      command.prepend("#{Shellwords.escape(k.to_s)}=#{Shellwords.escape(v.to_s)} ")
    end

    output = `#{command} 2>&1`
    status = $?

    if !status.success?
      puts "Command failed: #{args.inspect}"
      puts "Output: #{output}"
      raise "Got exit status #{status.exitstatus} attempting to execute #{args.inspect}!"
    end

    true
  end

  desc "Generate rpm, deb, tar and zip artifacts"
  task "all" => ["prepare", "build"]
  task "docker_only" => ["prepare", "build_docker_full", "build_docker_oss", "build_docker_wolfi", "build_docker_observabilitySRE"]

  desc "Build all (jdk bundled and not) tar.gz and zip of default logstash plugins with all dependencies"
  task "archives" => ["prepare", "generate_build_metadata"] do
    #with bundled JDKs
    license_details = ['ELASTIC-LICENSE']
    @bundles_jdk = true
    create_archive_pack(license_details, "x86_64", "linux", "windows", "darwin")
    create_archive_pack(license_details, "arm64", "linux", "darwin")

    #without JDK
    safe_system("./gradlew bootstrap") #force the build of Logstash jars
    @bundles_jdk = false
    build_tar(*license_details, platform: '-no-jdk')
    build_zip(*license_details, platform: '-no-jdk')
  end

  desc "Build jdk bundled tar.gz of default logstash plugins with all dependencies for docker"
  task "archives_docker" => ["prepare", "generate_build_metadata"] do
    license_details = ['ELASTIC-LICENSE']
    @bundles_jdk = true
    create_archive_pack(license_details, "x86_64", "linux")
    create_archive_pack(license_details, "arm64", "linux")
    safe_system("./gradlew bootstrap") # force the build of Logstash jars
  end

  def create_archive_pack(license_details, arch, *oses, &tar_interceptor)
    oses.each do |os_name|
      puts("[artifact:archives] Building tar.gz/zip of default plugins for OS: #{os_name}, arch: #{arch}")
      create_single_archive_pack(os_name, arch, license_details, &tar_interceptor)
    end
  end

  def create_single_archive_pack(os_name, arch, license_details, &tar_interceptor)
    safe_system("./gradlew copyJdk -Pjdk_bundle_os=#{os_name} -Pjdk_arch=#{arch}")
    if arch == 'arm64'
      arch = 'aarch64'
    end
    case os_name
    when "linux"
      build_tar(*license_details, platform: "-linux-#{arch}", &tar_interceptor)
    when "windows"
      build_zip(*license_details, platform: "-windows-#{arch}")
    when "darwin"
      build_tar(*license_details, platform: "-darwin-#{arch}", &tar_interceptor)
    end
    safe_system("./gradlew deleteLocalJdk -Pjdk_bundle_os=#{os_name}")
  end

  # Create an archive pack using settings appropriate for the running machine
  def create_local_archive_pack(bundle_jdk)
    @bundles_jdk = bundle_jdk
    safe_system("./gradlew copyJdk") if bundle_jdk
    build_tar('ELASTIC-LICENSE')
    safe_system("./gradlew deleteLocalJdk") if bundle_jdk
  end

  desc "Build a not JDK bundled tar.gz of default logstash plugins with all dependencies"
  task "no_bundle_jdk_tar" => ["prepare", "generate_build_metadata"] do
    create_local_archive_pack(false)
  end

  desc "Build a JDK bundled tar.gz of default logstash plugins with all dependencies"
  task "bundle_jdk_tar" => ["prepare", "generate_build_metadata"] do
    create_local_archive_pack(true)
  end

  desc "Build all (jdk bundled and not) OSS tar.gz and zip of default logstash plugins with all dependencies"
  task "archives_oss" => ["prepare-oss", "generate_build_metadata"] do
    #with bundled JDKs
    @bundles_jdk = true
    license_details = ['APACHE-LICENSE-2.0', "-oss", oss_exclude_paths]
    create_archive_pack(license_details, "x86_64", "linux", "windows", "darwin")
    create_archive_pack(license_details, "arm64", "linux", "darwin")

    #without JDK
    @bundles_jdk = false
    safe_system("./gradlew bootstrap") #force the build of Logstash jars
    build_tar(*license_details, platform: '-no-jdk')
    build_zip(*license_details, platform: '-no-jdk')
  end

  desc "Build jdk bundled OSS tar.gz of default logstash plugins with all dependencies for docker"
  task "archives_docker_oss" => ["prepare-oss", "generate_build_metadata"] do
    #with bundled JDKs
    @bundles_jdk = true
    license_details = ['APACHE-LICENSE-2.0', "-oss", oss_exclude_paths]
    create_archive_pack(license_details, "x86_64", "linux")
    create_archive_pack(license_details, "arm64", "linux")
    safe_system("./gradlew bootstrap") # force the build of Logstash jars
  end

  desc "Build jdk bundled tar.gz of observabilitySRE logstash plugins with all dependencies for docker"
  task "archives_docker_observabilitySRE" => ["prepare-observabilitySRE", "generate_build_metadata"] do
    #with bundled JDKs
    @bundles_jdk = true
    exclude_paths = default_exclude_paths + %w(
      bin/logstash-plugin
      bin/logstash-plugin.bat
      bin/logstash-keystore
      bin/logstash-keystore.bat
    )
    license_details = ['ELASTIC-LICENSE','-observability-sre', exclude_paths]
    %w(x86_64 arm64).each do |arch|
      create_archive_pack(license_details, arch, "linux") do |dedicated_directory_tar|
        # injection point: Use `DedicatedDirectoryTarball#write(source_file, destination_path)` to
        # copy additional files into the tarball
        puts "HELLO(#{dedicated_directory_tar})"
      end
    end
    safe_system("./gradlew bootstrap") # force the build of Logstash jars
  end

  desc "Build an RPM of logstash with all dependencies"
  task "rpm" => ["prepare", "generate_build_metadata"] do
    #with bundled JDKs
    @bundles_jdk = true
    puts("[artifact:rpm] building rpm package x86_64")
    package_with_jdk("centos", "x86_64")

    puts("[artifact:rpm] building rpm package arm64")
    package_with_jdk("centos", "arm64")

    #without JDKs
    @bundles_jdk = false
    safe_system("./gradlew bootstrap") #force the build of Logstash jars
    package("centos")
  end

  desc "Build an RPM of logstash with all dependencies"
  task "rpm_oss" => ["prepare-oss", "generate_build_metadata"] do
    #with bundled JDKs
    @bundles_jdk = true
    puts("[artifact:rpm] building rpm OSS package x86_64")
    package_with_jdk("centos", "x86_64", :oss)

    puts("[artifact:rpm] building rpm OSS package arm64")
    package_with_jdk("centos", "arm64", :oss)

    #without JDKs
    @bundles_jdk = false
    safe_system("./gradlew bootstrap") #force the build of Logstash jars
    package("centos", :oss)
  end

  desc "Build a DEB of logstash with all dependencies"
  task "deb" => ["prepare", "generate_build_metadata"] do
    #with bundled JDKs
    @bundles_jdk = true
    puts("[artifact:deb] building deb package for x86_64")
    package_with_jdk("ubuntu", "x86_64")

    puts("[artifact:deb] building deb package for OS: linux arm64")
    package_with_jdk("ubuntu", "arm64")

    #without JDKs
    @bundles_jdk = false
    safe_system("./gradlew bootstrap") #force the build of Logstash jars
    package("ubuntu")
  end

  desc "Build a DEB of logstash with all dependencies"
  task "deb_oss" => ["prepare-oss", "generate_build_metadata"] do
    #with bundled JDKs
    @bundles_jdk = true
    puts("[artifact:deb_oss] building deb OSS package x86_64")
    package_with_jdk("ubuntu", "x86_64", :oss)

    puts("[artifact:deb_oss] building deb OSS package arm64")
    package_with_jdk("ubuntu", "arm64", :oss)

    #without JDKs
    @bundles_jdk = false
    safe_system("./gradlew bootstrap") #force the build of Logstash jars
    package("ubuntu", :oss)
  end

  desc "Generate logstash core gems"
  task "gems" => ["prepare"] do
    Rake::Task["artifact:build-logstash-core"].invoke
    Rake::Task["artifact:build-logstash-core-plugin-api"].invoke
  end

  # "all-plugins" version of tasks
  desc "Generate rpm, deb, tar and zip artifacts (\"all-plugins\" version)"
  task "all-all-plugins" => ["prepare-all", "build"]

  desc "Build a zip of all logstash plugins from logstash-plugins github repo"
  task "zip-all-plugins" => ["prepare-all", "generate_build_metadata"] do
    puts("[artifact:zip] Building zip of all plugins")
    build_zip('ELASTIC-LICENSE', "-all-plugins")
  end

  desc "Build a tar.gz of all logstash plugins from logstash-plugins github repo"
  task "tar-all-plugins" => ["prepare-all", "generate_build_metadata"] do
    puts("[artifact:tar] Building tar.gz of all plugins")
    build_tar('ELASTIC-LICENSE', "-all-plugins")
  end

  desc "Build docker image"
  task "docker" => ["prepare", "generate_build_metadata", "archives_docker"] do
    puts("[docker] Building docker image")
    build_docker('full')
  end

  desc "Build OSS docker image"
  task "docker_oss" => ["prepare-oss", "generate_build_metadata", "archives_docker_oss"] do
    puts("[docker_oss] Building OSS docker image")
    build_docker('oss')
  end

  desc "Build observabilitySRE docker image"
  task "docker_observabilitySRE" => ["prepare-observabilitySRE", "generate_build_metadata", "archives_docker_observabilitySRE"] do
    puts("[docker_observabilitySRE] Building observabilitySRE docker image")
    build_docker('observability-sre')
  end

  desc "Build wolfi docker image"
  task "docker_wolfi" => %w(prepare generate_build_metadata archives_docker) do
    puts("[docker_wolfi] Building Wolfi docker image")
    build_docker('wolfi')
  end

  desc "Generate Dockerfiles for full and oss images"
  task "dockerfiles" => ["prepare", "generate_build_metadata"] do
    puts("[dockerfiles] Building Dockerfiles")
    build_dockerfile('oss')
    build_dockerfile('full')
    build_dockerfile('wolfi')
    build_dockerfile('observability-sre')
    build_dockerfile('ironbank')
  end

  desc "Generate Dockerfile for oss images"
  task "dockerfile_oss" => ["prepare-oss", "generate_build_metadata"] do
    puts("[dockerfiles] Building oss Dockerfile")
    build_dockerfile('oss')
  end

  namespace "dockerfile_oss" do
    desc "Build Oss Docker image from Dockerfile context files"
    task "docker" => ["archives_docker", "dockerfile_oss"]  do
      build_docker_from_dockerfiles('oss')
    end
  end

  desc "Generate Dockerfile for observability-sre images"
  task "dockerfile_observabilitySRE" => ["prepare-observabilitySRE", "generate_build_metadata"] do
    puts("[dockerfiles] Building observability-sre Dockerfile")
    build_dockerfile('observability-sre')
  end

  namespace "dockerfile_observabilitySRE" do
    desc "Build ObservabilitySrE Docker image from Dockerfile context files"
    task "docker" => ["archives_docker_observabilitySRE", "dockerfile_observabilitySRE"] do
      build_docker_from_dockerfiles('observability-sre')
    end
  end

  desc "Generate Dockerfile for full images"
  task "dockerfile_full" => ["prepare", "generate_build_metadata"] do
    puts("[dockerfiles] Building full Dockerfiles")
    build_dockerfile('full')
  end

  namespace "dockerfile_full" do
    desc "Build Full Docker image from Dockerfile context files"
    task "docker" => ["archives_docker", "dockerfile_full"]  do
      build_docker_from_dockerfiles('full')
    end
  end

  desc "Generate Dockerfile for wolfi images"
  task "dockerfile_wolfi" => ["prepare", "generate_build_metadata"] do
    puts("[dockerfiles] Building wolfi Dockerfiles")
    build_dockerfile('wolfi')
  end

  namespace "dockerfile_wolfi" do
    desc "Build Wolfi Docker image from Dockerfile context files"
    task "docker" => ["archives_docker", "dockerfile_wolfi"]  do
      build_docker_from_dockerfiles('wolfi')
    end
  end

  desc "Generate build context for ironbank"
  task "dockerfile_ironbank" => ["prepare", "generate_build_metadata"] do
    puts("[dockerfiles] Building ironbank Dockerfiles")
    build_dockerfile('ironbank')
  end

  # Auxiliary tasks
  task "build" => [:generate_build_metadata] do
    Rake::Task["artifact:gems"].invoke unless SNAPSHOT_BUILD
    Rake::Task["artifact:deb"].invoke
    Rake::Task["artifact:rpm"].invoke
    Rake::Task["artifact:archives"].invoke

    unless ENV['SKIP_DOCKER'] == "1"
      Rake::Task["artifact:docker"].invoke
      Rake::Task["artifact:docker_wolfi"].invoke
      Rake::Task["artifact:dockerfiles"].invoke
      Rake::Task["artifact:docker_oss"].invoke
      Rake::Task["artifact:docker_observabilitySRE"].invoke
    end

    Rake::Task["artifact:deb_oss"].invoke
    Rake::Task["artifact:rpm_oss"].invoke
    Rake::Task["artifact:archives_oss"].invoke
  end

  task "build_docker_full" => [:generate_build_metadata] do
    Rake::Task["artifact:docker"].invoke
    Rake::Task["artifact:dockerfile_full"].invoke
    Rake::Task["artifact:dockerfile_full:docker"].invoke
  end

  task "build_docker_oss" => [:generate_build_metadata] do
    Rake::Task["artifact:docker_oss"].invoke
    Rake::Task["artifact:dockerfile_oss"].invoke
    Rake::Task["artifact:dockerfile_oss:docker"].invoke
  end

  task "build_docker_observabilitySRE" => [:generate_build_metadata] do
    Rake::Task["artifact:docker_observabilitySRE"].invoke
    Rake::Task["artifact:dockerfile_observabilitySRE"].invoke
    Rake::Task["artifact:dockerfile_observabilitySRE:docker"].invoke
  end

  task "build_docker_wolfi" => [:generate_build_metadata] do
    Rake::Task["artifact:docker_wolfi"].invoke
    Rake::Task["artifact:dockerfile_wolfi"].invoke
    Rake::Task["artifact:dockerfile_wolfi:docker"].invoke
  end

  task "generate_build_metadata" do
    require 'time'
    require 'tempfile'

    return if defined?(BUILD_METADATA_FILE)
    BUILD_METADATA_FILE = Tempfile.new('build.rb')
    BUILD_DATE = Time.now.iso8601
    build_info = {
      "build_date" => BUILD_DATE,
      "build_sha" => `git rev-parse HEAD`.chomp,
      "build_snapshot" => SNAPSHOT_BUILD
    }

    metadata = ["# encoding: utf-8", "BUILD_INFO = #{build_info}"]
    IO.write(BUILD_METADATA_FILE.path, metadata.join("\n"))
  end

  # We create an empty bundle config file
  # This will allow the deb and rpm to create a file
  # with the correct user group and permission.
  task "clean-bundle-config" do
    FileUtils.mkdir_p(".bundle")
    File.open(".bundle/config", "w") { }
  end

  # locate the "gem "logstash-core" ..." line in Gemfile, and if the :path => "..." option if specified
  # build the local logstash-core gem otherwise just do nothing, bundler will deal with it.
  task "build-logstash-core" do
    # regex which matches a Gemfile gem definition for the logstash-core gem and captures the :path option
    gem_line_regex = /^\s*gem\s+["']logstash-core["'](?:\s*,\s*["'][^"^']+["'])?(?:\s*,\s*:path\s*=>\s*["']([^"^']+)["'])?/i

    lines = File.readlines("Gemfile")
    matches = lines.select {|line| line[gem_line_regex]}
    abort("ERROR: Gemfile format error, need a single logstash-core gem specification") if matches.size != 1

    path = matches.first[gem_line_regex, 1]

    if path
      Rake::Task["plugin:build-local-core-gem"].invoke("logstash-core", path)
    else
      puts "The Gemfile should reference \"logstash-core\" gem locally through :path, but found instead: #{matches}"
      exit(1)
    end
  end

  # locate the "gem "logstash-core-plugin-api" ..." line in Gemfile, and if the :path => "..." option if specified
  # build the local logstash-core-plugin-api gem otherwise just do nothing, bundler will deal with it.
  task "build-logstash-core-plugin-api" do
    # regex which matches a Gemfile gem definition for the logstash-core gem and captures the :path option
    gem_line_regex = /^\s*gem\s+["']logstash-core-plugin-api["'](?:\s*,\s*["'][^"^']+["'])?(?:\s*,\s*:path\s*=>\s*["']([^"^']+)["'])?/i

    lines = File.readlines("Gemfile")
    matches = lines.select {|line| line[gem_line_regex]}
    abort("ERROR: Gemfile format error, need a single logstash-core-plugin-api gem specification") if matches.size != 1

    path = matches.first[gem_line_regex, 1]

    if path
      Rake::Task["plugin:build-local-core-gem"].invoke("logstash-core-plugin-api", path)
    else
      puts "The Gemfile should reference \"logstash-core-plugin-api\" gem locally through :path, but found instead: #{matches}"
      exit(1)
    end
  end

  task "prepare" do
    if ENV['SKIP_PREPARE'] != "1"
      ["bootstrap", "plugin:install-default", "artifact:clean-bundle-config"].each {|task| Rake::Task[task].invoke }
    end
  end

  task "prepare-oss" do
    if ENV['SKIP_PREPARE'] != "1"
      %w[bootstrap plugin:install-default plugin:remove-non-oss-plugins artifact:clean-bundle-config].each {|task| Rake::Task[task].invoke }
    end
  end

  task "prepare-observabilitySRE" do
    if ENV['SKIP_PREPARE'] != "1"
      Rake::Task['bootstrap'].invoke
      Rake::Task['plugin:install-default'].invoke
      Rake::Task['plugin:install'].invoke('logstash-filter-age')
      Rake::Task['plugin:trim-for-observabilitySRE'].invoke
      Rake::Task['plugin:install-fips-validation-plugin'].invoke
      Rake::Task['artifact:clean-bundle-config'].invoke
    end
  end

  def ensure_logstash_version_constant_defined
    # we do not want this file required when rake (ruby) parses this file
    # only when there is a task executing, not at the very top of this file
    if !defined?(LOGSTASH_VERSION)
      require "logstash/version"
    end
  end

  def build_tar(license, tar_suffix = nil, exclude_paths = default_exclude_paths, platform: '', &tar_interceptor)
    require "zlib"
    require 'rubygems'
    require 'rubygems/package'
    require 'minitar'
    ensure_logstash_version_constant_defined
    tarpath = "build/logstash#{tar_suffix}-#{LOGSTASH_VERSION}#{PACKAGE_SUFFIX}#{platform}.tar.gz"
    if File.exist?(tarpath) && ENV['SKIP_PREPARE'] == "1" && !source_modified_since?(File.mtime(tarpath))
      puts("[artifact:tar] Source code not modified. Skipping build of #{tarpath}")
      return
    end
    puts("[artifact:tar] building #{tarpath}")
    gz = Zlib::GzipWriter.new(File.new(tarpath, "wb"), Zlib::BEST_COMPRESSION)
    Minitar::Writer.open(gz) do |tar|
      dedicated_directory_tarball = DedicatedDirectoryTarball.new(tar, "logstash-#{LOGSTASH_VERSION}#{PACKAGE_SUFFIX}")
      files(exclude_paths).each do |path|
        dedicated_directory_tarball.write(path)
      end

      source_license_path = "licenses/#{license}.txt"
      fail("Missing source license: #{source_license_path}") unless File.exist?(source_license_path)
      dedicated_directory_tarball.write(source_license_path, "LICENSE.txt")

      # add build.rb to tar
      metadata_file_path_in_tar = File.join("logstash-core", "lib", "logstash", "build.rb")
      dedicated_directory_tarball.write(BUILD_METADATA_FILE.path, metadata_file_path_in_tar)

      # yield to the tar interceptor if we have one
      yield(dedicated_directory_tarball) if block_given?
    end
    gz.close
  end

  ##
  # A `DedicatedDirectoryTarball` writes everything into a dedicated
  # directory that is known at init-time (e.g., NOT a tarbomb). All paths are
  class DedicatedDirectoryTarball
    def initialize(minitar_writer, dedicated_directory)
      @minitar_writer = minitar_writer
      @dedicated_directory = Pathname.new(dedicated_directory)
    end

    ##
    # Write the contents of the file, directory, or symlink in `source_path` to
    # the `destination_path` inside the tarball's dedicated directory.
    # @param source_path [String]: the path to the file to copy, relative to PWD
    # @param destination_path [String]: the path, relative to the tarball's dedicated directory, to
    #                                   write to (default: `source_path`)
    # @return [void]
    def write(source_path, destination_path=source_path)
      write_to_tar(@minitar_writer, source_path, expand(destination_path))

      nil
    end

    def to_s
      "#<#{self.class.name}:#{@dedicated_directory}>"
    end

    private

    ##
    # Expands the given `destination_path` relative to the dedicated directory,
    # ensuring that the result is inside the dedicated directory
    # @param destination_path [String]
    # @return [String]
    def expand(destination_path)
      expanded_destination_path = @dedicated_directory / destination_path
      fail("illegal destination path `#{destination_path}`") unless expanded_destination_path.descend.peek == @dedicated_directory

      expanded_destination_path.to_s
    end

    def write_to_tar(tar, path, path_in_tar)
      stat = File.lstat(path)
      if stat.directory?
        tar.mkdir(path_in_tar, :mode => stat.mode)
      elsif stat.symlink?
        tar.symlink(path_in_tar, File.readlink(path), :mode => stat.mode)
      else
        tar.add_file_simple(path_in_tar, :mode => stat.mode, :size => stat.size) do |io|
          File.open(path, 'rb') do |fd|
            chunk = nil
            size = 0
            size += io.write(chunk) while chunk = fd.read(16384)
            if stat.size != size
              raise "Failure to write the entire file (#{path}) to the tarball. Expected to write #{stat.size} bytes; actually write #{size}"
            end
          end
        end
      end
    end
  end

  def build_zip(license, zip_suffix = "", exclude_paths = default_exclude_paths, platform: '')
    require 'zip'
    ensure_logstash_version_constant_defined
    zippath = "build/logstash#{zip_suffix}-#{LOGSTASH_VERSION}#{PACKAGE_SUFFIX}#{platform}.zip"
    puts("[artifact:zip] building #{zippath}")
    File.unlink(zippath) if File.exist?(zippath)
    Zip::File.open(zippath, Zip::File::CREATE) do |zipfile|
      files(exclude_paths).each do |path|
        path_in_zip = "logstash-#{LOGSTASH_VERSION}#{PACKAGE_SUFFIX}/#{path}"
        zipfile.add(path_in_zip, path)
      end

      source_license_path = "licenses/#{license}.txt"
      fail("Missing source license: #{source_license_path}") unless File.exist?(source_license_path)
      zipfile.add("logstash-#{LOGSTASH_VERSION}#{PACKAGE_SUFFIX}/LICENSE.txt", source_license_path)

      # add build.rb to zip
      metadata_file_path_in_zip = File.join("logstash-core", "lib", "logstash", "build.rb")
      path_in_zip = File.join("logstash-#{LOGSTASH_VERSION}#{PACKAGE_SUFFIX}", metadata_file_path_in_zip)
      path = BUILD_METADATA_FILE.path
      Zip.continue_on_exists_proc = true
      zipfile.add(path_in_zip, path)
    end
    puts "Complete: #{zippath}"
  end

  def package_with_jdk(platform, jdk_arch, variant = :standard)
    safe_system("./gradlew copyJdk -Pjdk_bundle_os=linux -Pjdk_arch=#{jdk_arch}")
    package(platform, variant, true, jdk_arch)
    safe_system('./gradlew deleteLocalJdk -Pjdk_bundle_os=linux')
  end

  def package(platform, variant = :standard, bundle_jdk = false, jdk_arch = 'x86_64')
    oss = variant == :oss

    require "stud/temporary"
    require "fpm/errors" # TODO(sissel): fix this in fpm
    require "fpm/package/dir"
    require "fpm/package/gem" # TODO(sissel): fix this in fpm; rpm needs it.

    basedir = File.join(File.dirname(__FILE__), "..")
    dir = FPM::Package::Dir.new
    dir.attributes[:workdir] = File.join(basedir, "build", "fpm")

    metadata_file_path = File.join("logstash-core", "lib", "logstash", "build.rb")
    metadata_source_file_path = BUILD_METADATA_FILE.path
    dir.input("#{metadata_source_file_path}=/usr/share/logstash/#{metadata_file_path}")

    suffix = ""
    if oss
      suffix = "-oss"
      exclude_paths = oss_exclude_paths
    else
      exclude_paths = default_exclude_paths
    end

    files(exclude_paths).each do |path|
      next if File.directory?(path)
      # Omit any config dir from /usr/share/logstash for packages, since we're
      # using /etc/logstash below
      next if path.start_with?("config/")
      dir.input("#{path}=/usr/share/logstash/#{path}")
    end

    if oss
      # Artifacts whose sources are exclusively licensed under the Apache License and
      # Apache-compatible licenses are distributed under the Apache License 2.0
      dir.input("licenses/APACHE-LICENSE-2.0.txt=/usr/share/logstash/LICENSE.txt")
    else
      # Artifacts whose sources include Elastic Commercial Software are distributed
      # under the Elastic License.
      dir.input("licenses/ELASTIC-LICENSE.txt=/usr/share/logstash/LICENSE.txt")
    end

    # Create an empty /var/log/logstash/ directory in the package
    # This is a bit obtuse, I suppose, but it is necessary until
    # we find a better way to do this with fpm.
    Stud::Temporary.directory do |empty|
      dir.input("#{empty}/=/usr/share/logstash/data")
      dir.input("#{empty}/=/var/log/logstash")
      dir.input("#{empty}/=/var/lib/logstash")
      dir.input("#{empty}/=/etc/logstash/conf.d")
      dir.input("#{empty}/=/lib/systemd/system")
      dir.input("#{empty}/=/etc/default")
    end

    File.join(basedir, "config", "log4j2.properties").tap do |path|
      dir.input("#{path}=/etc/logstash")
    end

    arch_suffix = bundle_jdk ? map_architecture_for_package_type(platform, jdk_arch) : "no-jdk"

    ensure_logstash_version_constant_defined
    package_filename = "logstash#{suffix}-#{LOGSTASH_VERSION}#{PACKAGE_SUFFIX}-#{arch_suffix}.TYPE"

    File.join(basedir, "config", "startup.options").tap do |path|
      dir.input("#{path}=/etc/logstash")
    end
    File.join(basedir, "config", "jvm.options").tap do |path|
      dir.input("#{path}=/etc/logstash")
    end
    File.join(basedir, "config", "logstash.yml").tap do |path|
      dir.input("#{path}=/etc/logstash")
    end
    File.join(basedir, "config", "logstash-sample.conf").tap do |path|
      dir.input("#{path}=/etc/logstash")
    end
    File.join(basedir, "pkg", "pipelines.yml").tap do |path|
      dir.input("#{path}=/etc/logstash")
    end
    File.join(basedir, "pkg", "service_templates", "systemd", "lib", "systemd", "system", "logstash.service").tap do |path|
      dir.input("#{path}=/lib/systemd/system")
    end
    File.join(basedir, "pkg", "service_templates", "sysv", "etc", "default", "logstash").tap do |path|
      dir.input("#{path}=/etc/default")
    end

    case platform
      when "redhat", "centos"
        require "fpm/package/rpm"

        # Red Hat calls 'Apache Software License' == ASL
        license = oss ? "ASL 2.0" : "Elastic License"

        out = dir.convert(FPM::Package::RPM)
        out.license = license
        out.attributes[:rpm_use_file_permissions] = true
        out.attributes[:rpm_user] = "root"
        out.attributes[:rpm_group] = "root"
        out.attributes[:rpm_os] = "linux"
        out.attributes[:rpm_digest] = "sha256"
        out.config_files << "/etc/logstash/startup.options"
        out.config_files << "/etc/logstash/jvm.options"
        out.config_files << "/etc/logstash/log4j2.properties"
        out.config_files << "/etc/logstash/logstash.yml"
        out.config_files << "/etc/logstash/logstash-sample.conf"
        out.config_files << "/etc/logstash/pipelines.yml"
        out.config_files << "/lib/systemd/system/logstash.service"
        out.config_files << "/etc/default/logstash"
        out.replaces << "logstash < 7.10.0"
      when "debian", "ubuntu"
        require "fpm/package/deb"

        license = oss ? "ASL-2.0" : "Elastic-License"

        out = dir.convert(FPM::Package::Deb)
        out.license = license
        out.attributes[:deb_user] = "root"
        out.attributes[:deb_group] = "root"
        out.attributes[:deb_suggests] = ["java11-runtime-headless"] unless bundle_jdk
        out.config_files << "/etc/logstash/startup.options"
        out.config_files << "/etc/logstash/jvm.options"
        out.config_files << "/etc/logstash/log4j2.properties"
        out.config_files << "/etc/logstash/logstash.yml"
        out.config_files << "/etc/logstash/logstash-sample.conf"
        out.config_files << "/etc/logstash/pipelines.yml"
        out.config_files << "/lib/systemd/system/logstash.service"
        out.config_files << "/etc/default/logstash"
        out.conflicts << "logstash (<< 7.10.0)"
        out.replaces << "logstash (<< 7.10.0)"
    end

    # Packaging install/removal scripts
    ["before", "after"].each do |stage|
      ["install", "remove"].each do |action|
        script = "#{stage}-#{action}" # like, "before-install"
        script_sym = script.gsub("-", "_").to_sym
        script_path = File.join(File.dirname(__FILE__), "..", "pkg", platform, "#{script}.sh")
        next unless File.exist?(script_path)

        out.scripts[script_sym] = File.read(script_path)
      end
    end

    # TODO(sissel): Invoke Pleaserun to generate the init scripts/whatever

    out.name = oss ? "logstash-oss" : "logstash"
    out.architecture = bundle_jdk ? map_architecture_for_package_type(platform, jdk_arch) : "all"
    out.version = "#{LOGSTASH_VERSION}#{PACKAGE_SUFFIX}".gsub(/[.-]([[:alpha:]])/, '~\1')
    # TODO(sissel): Include the git commit hash?
    out.iteration = "1" # what revision?
    out.url = "https://www.elastic.co/logstash"
    out.description = "An extensible logging pipeline"
    out.vendor = "Elastic"

    # Because we made a mistake in naming the RC version numbers, both rpm and deb view
    # "1.5.0.rc1" higher than "1.5.0". Setting the epoch to 1 ensures that we get a kind
    # of clean slate as to how we compare package versions. The default epoch is 0, and
    # epoch is sorted first, so a version 1:1.5.0 will have greater priority
    # than 1.5.0.rc4
    out.epoch = 1

    # We don't specify a dependency on Java because:
    # - On Red Hat, Oracle and Red Hat both label their java packages in
    #   incompatible ways. Further, there is no way to guarantee a qualified
    #   version is available to install.
    # - On Debian and Ubuntu, there is no Oracle package and specifying a
    #   correct version of OpenJDK is impossible because there is no guarantee that
    #   is impossible for the same reasons as the Red Hat section above.
    # References:
    # - https://github.com/elastic/logstash/issues/6275
    # - http://www.elasticsearch.org/blog/java-1-7u55-safe-use-elasticsearch-lucene/
    # - deb: https://github.com/elasticsearch/logstash/pull/1008
    # - rpm: https://github.com/elasticsearch/logstash/pull/1290
    # - rpm: https://github.com/elasticsearch/logstash/issues/1673
    # - rpm: https://logstash.jira.com/browse/LOGSTASH-1020

    out.attributes[:force?] = true # overwrite the rpm/deb/etc being created
    begin
      path = File.join(basedir, "build", out.to_s(package_filename))
      x = out.output(path)
      puts "Completed: #{path}"
    ensure
      out.cleanup
    end
  end # def package

  def map_architecture_for_package_type(platform, jdk_arch)
    if jdk_arch == 'x86_64'
      case platform
        when "debian", "ubuntu"
          return "amd64"
        else
          return "x86_64"
      end
    elsif jdk_arch == 'arm64'
      case platform
        when "debian", "ubuntu"
          return "arm64"
        else
          return "aarch64"
      end
    else
      raise "CPU architecture not recognized: #{jdk_arch}"
    end
  end

  def build_docker(flavor)
    env = {
      "ARTIFACTS_DIR" => ::File.join(Dir.pwd, "build"),
      "RELEASE" => ENV["RELEASE"],
      "VERSION_QUALIFIER" => VERSION_QUALIFIER,
      "BUILD_DATE" => BUILD_DATE,
      "LOCAL_ARTIFACTS" => LOCAL_ARTIFACTS
    }
    Dir.chdir("docker") do |dir|
      safe_system(env, "make build-from-local-#{flavor}-artifacts")
    end
  end

  def build_docker_from_dockerfiles(flavor)
    env = {
      "ARTIFACTS_DIR" => ::File.join(Dir.pwd, "build"),
      "RELEASE" => ENV["RELEASE"],
      "VERSION_QUALIFIER" => VERSION_QUALIFIER,
      "BUILD_DATE" => BUILD_DATE,
      "LOCAL_ARTIFACTS" => LOCAL_ARTIFACTS
    }
    Dir.chdir("docker") do |dir|
      safe_system(env, "make build-from-dockerfiles_#{flavor}")
    end
  end

  def build_dockerfile(flavor)
    env = {
      "ARTIFACTS_DIR" => ::File.join(Dir.pwd, "build"),
      "RELEASE" => ENV["RELEASE"],
      "VERSION_QUALIFIER" => VERSION_QUALIFIER,
      "BUILD_DATE" => BUILD_DATE,
      "LOCAL_ARTIFACTS" => LOCAL_ARTIFACTS
    }
    Dir.chdir("docker") do |dir|
      safe_system(env, "make public-dockerfiles_#{flavor}")
      puts "Dockerfiles created in #{env['ARTIFACTS_DIR']}"
    end
  end
end
