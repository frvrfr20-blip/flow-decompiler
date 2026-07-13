local function values(...)
    return ...
end

local function relay(...)
    return values(...)
end

local first, second, third = values("one", "two", "three")
print(first, second, third)
print(relay("four", "five", "six"))
