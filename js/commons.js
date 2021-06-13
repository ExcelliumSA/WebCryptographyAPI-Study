/**
 * Contains commons functions used to render the lab.
 */

const TESTS_VALUES_LENGTH = [10, 100, 1000, 10000];

async function executeTest(testCaseId) {
    let results = new Map();
    let input, output = null;
    let start, end = 0;
    for (const v of TESTS_VALUES_LENGTH) {
        start = performance.now();
        switch (testCaseId) {
            case 1:
                input = v;
                output = performRandomValuesGeneration(input);
                break;
            case 2:
                input = "X".repeat(v);
                output = await performSha512Hash(input);
                break;
            default:
                output = "Unsupported!";
        }
        end = performance.now();
        results.set(v, {
            "Output": output,
            "Input": input,
            "ProcessingDelayInMS": (end - start).toFixed(4)
        });
    }
    console.debug("TEST CASE RESULTS:")
    console.debug(results);
    return results;
}

function renderTestResults(testCaseId) {
    executeTest(testCaseId).then(resultsMap => {
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
    }).catch(err => alert("ERROR: " + err));
}