// Core modules

// External modules
const lodash = require('lodash');
const nunjucks = require('nunjucks');

// Modules

let dirView = CONFIG.app.dirs.view; // Path to view directory

// Setup view
// Setup nunjucks loader. See https://mozilla.github.io/nunjucks/api.html#loader
let loaderFsNunjucks = new nunjucks.FileSystemLoader(dirView, CONFIG.nunjucks.loader);

// Setup nunjucks environment. See https://mozilla.github.io/nunjucks/api.html#environment
let env = new nunjucks.Environment(loaderFsNunjucks, CONFIG.nunjucks.environment);

// Add filters

// Custom app specific filter
env.addFilter('s3_url', function (value, sizePrefix = "") {
    if (sizePrefix) {
        sizePrefix += "-";
    }
    return `/file-getter/${CONFIG.aws.bucket1.name}/${CONFIG.aws.bucket1.prefix}/${sizePrefix}${value}`
})

env.addFilter('view_url', function (value, sizePrefix = "") {
    if (sizePrefix) {
        sizePrefix += "-";
    }
    return `/file-viewer/${CONFIG.aws.bucket1.name}/${CONFIG.aws.bucket1.prefix}/${sizePrefix}${value}`
})

env.addFilter('customFilter', function (array, filterObj) {
    return lodash.filter(array, filterObj)
})

env.addFilter('mapValue', function (value, list) {
    return lodash.get(lodash.find(list, (o) => o.value === value), 'text', '')
})

env.addFilter('generateArray', function (value, offset = 0) {
    return Array.from(Array(value).keys()).slice(offset)
})
env.addFilter('padStart', function (value, length = 2, pads = '0') {
    return String(value).padStart(length, pads)
})
env.addFilter('maybePluralize', function (count, noun, suffix = 's') {
    return`${count} ${noun}${count !== 1 ? suffix : ''}`;
})
env.addFilter('includes', function (array, value) {
    return array.includes(value);
})

// Export
module.exports = env;