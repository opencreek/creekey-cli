class Creekey < Formula
    version '0.1.0'
    desc "Keep your private keys on your phone!"
    homepage "https://creekey.io"
    license
    if os.map?
        url "https://github.com/opencreek/creekey-cli/"
    end
    head do
        "https://github.com/"
    end

    depends_on "rust" => [":build"]
    depends_on "cargo" => [":build"]

    def install
        system "cargo", "build", "--release"

        bin.install "target/release/creekey"
        bin.install "target/release/creekey-git-sign"

        prefix.install_symlink "src/pkg/brew/service.plist" => "#{plist_name}.plist"
    end

    test do
        system "which creekey"
    end


    def caveats
        "Run 'creekey pair' to pair with your phone!"
    end
end
