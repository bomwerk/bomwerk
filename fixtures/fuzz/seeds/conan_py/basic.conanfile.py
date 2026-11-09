from conan import ConanFile


class App(ConanFile):
    requires = "zlib/1.2.13", "fmt/10.2.1"
    tool_requires = ["cmake/3.27.7"]

    def requirements(self):
        self.requires("openssl/3.2.0")
