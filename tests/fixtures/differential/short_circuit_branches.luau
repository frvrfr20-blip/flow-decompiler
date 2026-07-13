local probes = 0

local function probe(value)
    probes += 1
    return value
end

local function classify(value)
    if value < 0 then
        return "negative"
    end

    if value == 0 or value == 1 then
        return "small"
    end

    if value > 10 and (value % 2 == 0 or value == 13) then
        return "special"
    end

    return "other"
end

local selected = false and probe("skipped") or probe("chosen")
for _, value in ipairs({ -1, 0, 1, 11, 12, 13 }) do
    print(classify(value))
end
print(selected, probes)
