local bit = require("bit")

function file_exists(file)
  local f = io.open(file, "rb")
  if f then f:close() end
  return f ~= nil
end

function lines_from(file)
  if not file_exists(file) then return {} end
  lines = {}
  for line in io.lines(file) do
    lines[#lines + 1] = line
  end
  return lines
end

function ipToNumber(ip)
 if not ip then return false end
 local a,b,c,d=ip:match("^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$")
 a=tonumber(a)
 b=tonumber(b)
 c=tonumber(c)
 d=tonumber(d)
 if not a or not b or not c or not d then return false end
 if a<0 or 255<a then return false end
 if b<0 or 255<b then return false end
 if c<0 or 255<c then return false end
 if d<0 or 255<d then return false end
 return a*(256*256*256) + b*(256*256) + c*256 + d
end

local file = '/var/run/akhet/allowed-ip-api.txt'

if file_exists(file) then
  local lines = lines_from(file)

  allowed=false
  for k,entry in pairs(lines) do
    ip = entry
    mask_cidr = 32
    for new_ip, new_mask in string.gmatch(entry, "([^,]+)/([^,]+)") do
      ip = new_ip
      mask_cidr = tonumber(new_mask)
    end
    mask_number = 0
    for i=0,mask_cidr-1 do
      mask_number = mask_number + 2^(31-i)
    end

    ngx.log(ngx.ERR, "Check for " .. ngx.var.remote_addr .. " with " .. ip .. " / " .. mask_cidr)
    if bit.band(ipToNumber(ip), mask_number) == bit.band(ipToNumber(ngx.var.remote_addr), mask_number)  then
      ngx.log(ngx.ERR, "ALLOW")
      allowed=true
    end
  end

  if not allowed then
    ngx.exit(ngx.HTTP_FORBIDDEN)
    ngx.log(ngx.ERR, "Not Allowed: " .. ngx.var.remote_addr)
  end
end
