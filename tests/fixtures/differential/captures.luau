local function factorial(value)
    if value <= 1 then
        return 1
    end
    return value * factorial(value - 1)
end

local function make_tracker(seed)
    local captured_value = seed
    local captured_reference = { total = seed }

    return function(delta)
        captured_value += delta
        captured_reference.total += captured_value
        return factorial(captured_value), captured_reference.total
    end
end

local tracker = make_tracker(2)
print(tracker(1))
print(tracker(2))
