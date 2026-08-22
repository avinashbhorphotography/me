let s;const t=()=>s??=fetch("/posts.json").then(o=>{if(!o.ok)throw new Error("Failed to load posts.json");return o.json()});export{t as l};
