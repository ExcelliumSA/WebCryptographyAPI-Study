/**
 * Contains commons functions used to render the lab.
 */

const TESTS_VALUES_LENGTH = [10, 100, 1000, 10000];

function executeTest(testCaseId) {
    let results = new Map();
    let data = null;
    let start, end = 0;
    TESTS_VALUES_LENGTH.forEach(v => {
        start = performance.now();
        switch (testCaseId) {
            case 1:
                data = performRandomValuesGeneration(v);
                break;
            default:
                data = "Unsupported!";
        }
        end = performance.now();
        results.set(v, {
            "Data": data,
            "ProcessingDelayInMS": (end - start).toFixed(4)
        });
    })
    return results;
}

function renderTestResults(testCaseId) {
    let resultsMap = executeTest(testCaseId);
    let chartValues = [];
    resultsMap.forEach(function (value, key) {
        chartValues.push(value.ProcessingDelayInMS)
    });
    let data = {
        labels: TESTS_VALUES_LENGTH,
        datasets: [{
            label: "Processing delay",
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            borderColor: 'rgba(75, 192, 192, 0.2)',
            data: chartValues
        }]
    };
    let config = {
        type: "bar",
        data,
        options: {
            scales: {
                y: {
                    title: {
                        display: true,
                        text: "Time taken in milliseconds."
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: "Test values length."
                    }
                }
            }
        }
    };
    new Chart(
        document.getElementById("renderingTestResultsZone"), config
    );
}