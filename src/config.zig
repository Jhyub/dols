pub const ConfigFile = struct {
    port: ?u16,

    auth_try_limit: ?u32,
};

pub const Config = struct {
    port: u16,

    auth_try_limit: u32,

    pub fn init(from: ConfigFile) Config {
        return Config{
            .port = from.port orelse 22,
            .auth_try_limit = from.auth_try_limit orelse 0,
        };
    }
};