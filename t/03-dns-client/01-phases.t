use Test::Nginx::Socket;

no_long_string();

plan tests => repeat_each() * (blocks() * 4 + 1);

workers(6);

no_shuffle();
run_tests();

__DATA__

=== TEST 1: client supports access phase
--- http_config eval
qq {
    lua_shared_dict kong_dns_cache              12m;
    lua_shared_dict kong_dns_cache_ipc          12m;
}
--- config
    location = /t {
        access_by_lua_block {
            local client = require("kong.resty.dns.client")
            assert(client.init())
            local host = "localhost"
            local typ = client.TYPE_A
            local answers, err = client.resolve(host, { qtype = typ })

            if not answers then
                ngx.say("failed to resolve: ", err)
            end

            ngx.say("address name: ", answers[1].name)
        }
    }
--- request
GET /t
--- response_body
address name: localhost
--- no_error_log
[error]
dns lookup pool exceeded retries
API disabled in the context of init_worker_by_lua



=== TEST 2: client does not support init_worker phase
--- http_config eval
qq {
    lua_shared_dict kong_dns_cache              12m;
    lua_shared_dict kong_dns_cache_ipc          12m;
    init_worker_by_lua_block {
        local client = require("kong.resty.dns.client")
        assert(client.init())
        local host = "konghq.com"
        local typ = client.TYPE_A
        answers, err = client.resolve(host, { qtype = typ })
    }
}
--- config
    location = /t {
        access_by_lua_block {
            ngx.say("answers: ", answers)
            ngx.say("err: ", err)
        }
    }
--- request
GET /t
--- response_body_like chomp
err: callback threw an error: .* API disabled in the context of init_worker_by_lua
--- no_error_log
[error]
API disabled in the context of init_worker_by_lua
