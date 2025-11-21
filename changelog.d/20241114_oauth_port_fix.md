### Fixed

- Fixed OAuth server initialization that caused AttributeError when OS could not allocate a port. The server_port is now accessed only after successful HTTPServer creation.
