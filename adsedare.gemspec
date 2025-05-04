# frozen_string_literal: true

require_relative "lib/adsedare/version"

Gem::Specification.new do |spec|
  spec.name = "adsedare"
  spec.version = Adsedare::VERSION
  spec.authors = ["alexstrnik"]
  spec.email = ["alex.str.nik@gmail.com"]

  spec.summary = "A cross-platform library for seamless, pain-free iOS ad-hoc distribution."
  spec.description = "AdSedare is a powerful library designed to simplify the process of iOS ad-hoc distribution. By automating and streamlining the distribution of builds, it ensures a smooth, pain-free experience for developers and testers. AdSedare is ideal for anyone looking to automate the distribution of iOS apps, without the usual headaches associated with managing provisioning profiles, certificates, and manual setups."
  spec.homepage = "https://github.com/AlexStrNik/AdSedare"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/AlexStrNik/AdSedare"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .circleci appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "rake", "~> 13.0"
  spec.add_dependency "xcodeproj", "~> 1.27.0"
  spec.add_dependency "jwt", "~> 2.7"
  spec.add_dependency "faraday", "~> 2.7"
  spec.add_dependency "faraday-cookie_jar", "~> 0.0.7" 
  spec.add_dependency "plist", "~> 3.2.0"
end
