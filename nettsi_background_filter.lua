local my_info = {
	version = "1.0.0",
	author = "Alper Soylu",
	repository = ""
}

set_plugin_info(my_info)

-- Not supporting Tshark
if not gui_enabled() then return end

function invert_table(t)
	local s={}
	for k,v in pairs(t) do
		s[v]=k
	end
	return s
end	

function get_config_path()
    local f = "/nettsi_background_filter.config"
    if Dir.exists(Dir.personal_plugins_path()) then
        return (Dir.personal_plugins_path() .. f)
    else
        return (Dir.global_plugins_path() .. f)
    end
end
-- split("a,b,c", ",") => {"a", "b", "c"}
function split(s, sep)
    local fields = {}
    
    local sep = sep or " "
    local pattern = string.format("([^%s]+)", sep)
    string.gsub(s, pattern, function(c) fields[#fields + 1] = c end)
    
    return fields
end

function import_table()
    local config_path = get_config_path()
    print("import " .. config_path)
    local file = io.open(config_path, "r") 
    if not file then return nil end
    
    -- This will contain a hash of counters of appearances of a certain address
    local data = {}
    
    for line in io.lines(path) do
        local words = split(line, "=")   
        data[words[0]] = tonumber(words[1])
    end
    
    file:close()
    if next(data) ~= nil then
        set_background_filter()
    end
    display_table(ips)
    return data
end
 
function export_table(data)
    local config_path = get_config_path()
    print("export " .. config_path)
    local file = io.open(config_path, "w")
    if not file then return nil end
    local str = ""
    for k,v in pairs(data) do
        str = str .. k .. "=" .. tostring(v) .. "\n"
	end
    file:write(str)
    file:close()
end

function display_table(data)
    print("table")
    for k,v in pairs(data) do
        print(k .. ":\t" .. v .. "\n");
    end
end

-- This will contain a hash of counters of appearances of a certain address
ips = {} -- import_table() or {}


stages = {
	["idle"] = 1,
	-- ["configure"] = 1,
	["recording"] = 2,
	["set"] = 3,
	["apply"] = 4,
	["active"] = 5
}


stage_names = invert_table(stages)
stage = stages.idle 

packet_per_min = 3
start_time = 0


-- we need these fields from the ip packets
ip_src = Field.new("ip.src")
ip_dst = Field.new("ip.dst")
-- declare our postdissector
ip_ext = Proto("ip_ext","background traffic postdissector")

-- our fields
ip_src_idle_freq = ProtoField.uint32("ip_ext.src_idle_freq","Src IP Frequency")
ip_dst_idle_freq = ProtoField.uint32("ip_ext.dst_idle_freq","Dst IP Frequency")
ip_ext.fields = {ip_src_idle_freq, ip_dst_idle_freq}

function set_background_filter()
	-- info
	print("ip postdissector loaded")

	-- dissect each packet
	function ip_ext.dissector(buffer,pinfo,tree)
		local ipsrc = ip_src()
		local ipdst = ip_dst()
		-- print(string.format("%s(%d):%s(%d)", tostring(ipsrc), ips[tostring(ipsrc)] or 0, tostring(ipdst), ips[tostring(ipdst)] or 0))
		if (ipsrc) then
			local bg_subtree = tree:add(ip_ext, "Background Traffic Heuristics")
			bg_subtree:add(ip_src_idle_freq, tostring(ips[tostring(ipsrc)] or 0))
			bg_subtree:add(ip_dst_idle_freq, tostring(ips[tostring(ipdst)] or 0))
		end
	end -- end dissector function

	-- register ourselfs
    register_postdissector(ip_ext)
    -- for k,v in pairs(ips) do
    --     if v > packet_per_min then
    --         filter_str = filter_str .. "ip.src == " .. k
    --     end
    -- end
	filter_tmpl = "ip_ext.src_idle_freq < %d or ip_ext.dst_idle_freq < %d"
	filter_str = string.format(filter_tmpl, packet_per_min, packet_per_min)
    set_filter(filter_str)
end

-- This program will register a menu that will open a window with a count of occurrences
-- of every address in the capture

local function background_listener (duration)
    -- This will contain a hash of counters of appearances of a certain address
    -- ips = import_table() or {}

    -- start recording here
    -- Declare the window we will use
    local tw = TextWindow.new("Address Counter")

    local function log (msg, clear)
        tw:clear()
        tw:set("Stage " .. tostring(stage) .. ": " .. tostring(stage_names[stage]) .. "\n")
        for k,v in pairs(ips) do
            tw:append(k .. ":\t" .. v .. "\n");
        end
    end

    -- this is our tap
    local tap = Listener.new();

    local function remove()
        -- this way we remove the listener that otherwise will remain running indefinitely
        tap:remove();
    end

    -- we tell the window to call the remove() function when closed
    tw:set_atclose(remove)
    
    tw:add_button("start recording", 
        function () 
            if (stage == stages.idle) then 
                ips = {}
                stage = stages.recording 
                start_time = os.time()
                log()
            end 
        end
    )
    tw:add_button("stop recording", 
        function () 
            if (stage == stages.recording) then 
                stage = stages.set
                local recording_seconds = os.time() - start_time
                local factor = 60 / recording_seconds
                for k,v in pairs(ips) do
                    ips[k] = v * factor
                end
                set_background_filter()
                -- export_table(ips)
                log()
                display_table(ips)
            end 
        end
    )

    -- local finish_time = 0
    -- this function will be called once for each packet
    function tap.packet(pinfo,tvb)
        if stage == stages.recording then
            local src = ips[tostring(pinfo.src)] or 0
            local dst = ips[tostring(pinfo.dst)] or 0
            ips[tostring(pinfo.src)] = src + 1
            ips[tostring(pinfo.dst)] = dst + 1
            -- print(string.format("%s(%d):%s(%d)", tostring(pinfo.src), ips[tostring(pinfo.src)] or 0, tostring(pinfo.dst), ips[tostring(pinfo.dst)] or 0))
        end
    end

    -- this function will be called once every few seconds to update our window
    function tap.draw(t)
        log()
    end

    -- this function will be called whenever a reset is needed
    -- e.g. when reloading the capture file
    function tap.reset()
        tw:clear()
        -- ips = import_table()
        -- log()
    end

    -- Ensure that all existing packets are processed.
    retap_packets()
end

register_menu("Nettsi/BackgroundFilter", background_listener, MENU_TOOLS_UNSORTED)
