// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title LoopPlayground
 * @notice A contract with many for-loops of different shapes to exercise analyzers/IR.
 * - Plain counted loops
 * - unchecked i++ micro-optimizations
 * - Early break / continue
 * - Nested loops (O(n^2))
 * - 2D loops (matrix-style)
 * - "Iterating" mappings via a stored keys array
 * - Gas guards to bound work
 */
contract LoopPlayground {
    // --- Storage under test ---
    uint256[] public numbers;
    uint256[][] public grid; // ragged 2D
    mapping(address => uint256) public deposits;
    address[] public depositorKeys; // to scan mapping in a bounded way

    // --- Events to make traces obvious ---
    event SumResult(uint256 sum);
    event FoundAt(uint256 index, uint256 value);
    event Sorted(uint256[] arr);
    event MatrixDot(uint256 row, uint256 col, uint256 val);
    event Accumulated(uint256 total);
    event Filled(uint256 n);
    event UpdatedDeposit(address who, uint256 amount);

    // --- Helpers ---
    function _requireBound(uint256 n, uint256 maxN) internal pure {
        require(n <= maxN, "too-big");
    }

    constructor(uint256[] memory seed) {
        // seed numbers
        for (uint256 i = 0; i < seed.length; i++) {
            numbers.push(seed[i]);
        }
        // seed a small 2D grid: 3x3
        grid.push([uint256(1), 2, 3]);
        grid.push([uint256(4), 5, 6]);
        grid.push([uint256(7), 8, 9]);
    }

    // --- Basic counted loop ---
    function sumNumbersBounded(uint256 limit) external returns (uint256 s) {
        uint256 n = numbers.length;
        if (limit < n) n = limit; // bound work
        for (uint256 i = 0; i < n; i++) {
            s += numbers[i];
        }
        emit SumResult(s);
    }

    // --- Unchecked loop increment (gas micro-optimization) ---
    function sumUnchecked(uint256 limit) external returns (uint256 s) {
        uint256 n = numbers.length;
        if (limit < n) n = limit;
        for (uint256 i = 0; i < n; ) {
            s += numbers[i];
            unchecked { i++; }
        }
        emit SumResult(s);
    }

    // --- Early break + continue pattern ---
    function firstGreaterThan(uint256 x) external returns (int256 idx) {
        idx = -1;
        for (uint256 i = 0; i < numbers.length; i++) {
            uint256 v = numbers[i];
            if (v == x) { // skip equals
                continue;
            }
            if (v > x) {
                idx = int256(i);
                emit FoundAt(i, v);
                break;
            }
        }
    }

    // --- Nested loops (classic bubble sort; O(n^2)) ---
    function bubbleSortLocal(uint256 maxN) external returns (uint256[] memory arr) {
        uint256 n = numbers.length;
        _requireBound(n, maxN);
        arr = new uint256[](n);
        for (uint256 i = 0; i < n; i++) arr[i] = numbers[i];

        if (n < 2) {
            emit Sorted(arr);
            return arr;
        }

        for (uint256 i = 0; i < n - 1; i++) {
            for (uint256 j = 0; j < n - 1 - i; j++) {
                if (arr[j] > arr[j + 1]) {
                    uint256 tmp = arr[j];
                    arr[j] = arr[j + 1];
                    arr[j + 1] = tmp;
                }
            }
        }
        emit Sorted(arr);
    }

    // --- 2D nested loops (matrix dot-like op) ---
    function sumGridDots() external returns (uint256 total) {
        for (uint256 r = 0; r < grid.length; r++) {
            uint256[] storage row = grid[r];
            for (uint256 c = 0; c < row.length; c++) {
                uint256 v = row[c] * (r + 1) * (c + 1);
                total += v;
                emit MatrixDot(r, c, v);
            }
        }
        emit SumResult(total);
    }

    // --- Fill numbers with arithmetic sequence using a loop ---
    function fillSequence(uint256 n, uint256 start, uint256 step, uint256 maxN) external {
        _requireBound(n, maxN);
        delete numbers;
        numbers = new uint256[](n);
        uint256 cur = start;
        for (uint256 i = 0; i < n; i++) {
            numbers[i] = cur;
            cur += step;
        }
        emit Filled(n);
    }

    // --- Append many using unchecked increments (gas) ---
    function appendMany(uint256 n, uint256 base, uint256 maxN) external {
        _requireBound(n, maxN);
        for (uint256 i = 0; i < n; ) {
            numbers.push(base + i);
            unchecked { i++; }
        }
        emit Filled(numbers.length);
    }

    // --- Bounded "iteration" over mapping via a stored keys array ---
    function deposit() external payable {
        if (deposits[msg.sender] == 0) {
            depositorKeys.push(msg.sender);
        }
        deposits[msg.sender] += msg.value;
        emit UpdatedDeposit(msg.sender, deposits[msg.sender]);
    }

    function accumulateDeposits(uint256 limit) external returns (uint256 total, uint256 counted) {
        uint256 n = depositorKeys.length;
        if (limit < n) n = limit;
        for (uint256 i = 0; i < n; i++) {
            total += deposits[depositorKeys[i]];
        }
        emit Accumulated(total);
        return (total, n);
    }

    // --- Triangular-number style nested loop (O(n^2/2)) ---
    function triangularAccumulate(uint256 n, uint256 maxN) external pure returns (uint256 total) {
        // pure + loops → easy target for analyzers
        require(n <= maxN, "too-big");
        for (uint256 i = 1; i <= n; i++) {
            for (uint256 j = 1; j <= i; j++) {
                total += j;
            }
        }
        // no event (pure)
    }

    // --- Mixed read/write inside nested loops with bounds ---
    function scaledAddToGrid(uint256 scale, uint256 maxCells) external returns (uint256 cellsTouched) {
        uint256 touched = 0;
        for (uint256 r = 0; r < grid.length; r++) {
            uint256[] storage row = grid[r];
            for (uint256 c = 0; c < row.length; c++) {
                grid[r][c] = row[c] + scale;
                touched++;
                if (touched >= maxCells) {
                    emit SumResult(touched);
                    return touched; // early exit
                }
            }
        }
        emit SumResult(touched);
        return touched;
    }

    // --- Utilities to grow the 2D grid safely ---
    function pushRow(uint256[] calldata row, uint256 maxCols) external {
        _requireBound(row.length, maxCols);
        grid.push(row);
    }

    // View helpers for tests
    function numbersLen() external view returns (uint256) { return numbers.length; }
    function gridDims() external view returns (uint256 rows, uint256 cols0) {
        rows = grid.length;
        cols0 = rows == 0 ? 0 : grid[0].length;
    }
}
