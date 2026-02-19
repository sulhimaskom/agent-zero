import * as initializer from "./initializer.min.js";
import * as _modals from "./modals.min.js";
import * as _components from "./components.min.js";

// initialize required elements
await initializer.initialize();

// import alpine library
await import("../vendor/alpine/alpine.min.js");

// add x-destroy directive to alpine
Alpine.directive(
  "destroy",
  (el, { expression }, { evaluateLater, cleanup }) => {
    const onDestroy = evaluateLater(expression);
    cleanup(() => onDestroy());
  }
);

// add x-create directive to alpine
Alpine.directive("create", (_el, { expression }, { evaluateLater }) => {
  const onCreate = evaluateLater(expression);
  onCreate();
});
