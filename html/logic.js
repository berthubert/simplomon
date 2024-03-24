"use strict";


async function doPageLoad(f) {
    const response = await fetch('checker-states');
    if (response.ok === true) {
        const data = await response.json();
        f.all = data;

        for (const [key, value] of Object.entries(data)) {
            f.all[key].cols={};
            f.all[key].rcols={};
            for (const element of value) {
                for(const [akey, avalue] of Object.entries(element.attr)) {
                    f.all[key].cols[akey]=1;
                }
                for(const [akey, avalue] of Object.entries(element.results)) {
                    for(const [rkey, rvalue] of Object.entries(avalue)) {
                        f.all[key].rcols[rkey]=2;
                    }
                }
            }
        }
    }

    const response2 = await fetch('state');
    if (response2.ok === true) {
        const data = await response2.json();
        f.alerts = data.alerts
    }

}

