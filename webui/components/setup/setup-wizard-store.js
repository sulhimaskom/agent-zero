import { createStore } from '/js/AlpineStore.js';
import { sendJsonData } from '/js/api.js';
import { API_ENDPOINTS } from '/js/constants.js';
import Logger from '/js/logger.js';

const model = {
  // State
  isOpen: false,
  currentStep: 0,
  totalSteps: 5,

  // Wizard data
  selectedProvider: null,
  apiKey: '',
  selectedChatModel: null,
  selectedUtilModel: null,
  isValidating: false,
  validationError: null,
  isComplete: false,

  // Provider data (loaded from backend)
  providers: [],
  chatModels: [],
  utilModels: [],

  // Step definitions
  steps: [
    { id: 'welcome', title: 'Welcome', description: 'Get started with Agent Zero' },
    { id: 'provider', title: 'Provider', description: 'Choose your AI provider' },
    { id: 'apikey', title: 'API Key', description: 'Enter your API key' },
    { id: 'model', title: 'Models', description: 'Select your models' },
    { id: 'review', title: 'Review', description: 'Review your configuration' },
  ],

  // Initialize the wizard
  async init() {
    // Load providers from settings
    try {
      const response = await sendJsonData(API_ENDPOINTS.SETTINGS_GET, null);
      if (response.settings && response.settings.sections) {
        // Find provider sections in settings
        const agentSection = response.settings.sections.find(s => s.tab === 'agent');
        if (agentSection && agentSection.fields) {
          // Extract providers from dropdown fields
          const providerField = agentSection.fields.find(f => f.id === 'chat_model_provider');
          if (providerField && providerField.options) {
            this.providers = providerField.options.map(opt => ({
              id: opt.value,
              name: opt.label,
              description: this.getProviderDescription(opt.value),
            }));
          }
        }
      }
    } catch (e) {
      Logger.error('Failed to load providers:', e);
      window.toastFrontendWarning(
        'Could not load providers from settings. Using defaults.',
        'Provider Load',
        5,
      );
      // Fallback to default providers
      this.providers = this.getDefaultProviders();
    }
  },

  // Get default providers if API fails
  getDefaultProviders() {
    return [
      { id: 'openai', name: 'OpenAI', description: 'GPT-4, GPT-4 Turbo, GPT-3.5' },
      { id: 'anthropic', name: 'Anthropic', description: 'Claude 3.5, Claude 3' },
      { id: 'google', name: 'Google', description: 'Gemini Pro, Gemini Ultra' },
      { id: 'deepseek', name: 'DeepSeek', description: 'DeepSeek Chat, DeepSeek Coder' },
      { id: 'openrouter', name: 'OpenRouter', description: 'Access to 100+ models' },
      { id: 'ollama', name: 'Ollama', description: 'Local AI models' },
      { id: 'lm_studio', name: 'LM Studio', description: 'Local AI models' },
    ];
  },

  // Get provider description
  getProviderDescription(providerId) {
    const descriptions = {
      'openai': 'GPT-4, GPT-4 Turbo, GPT-3.5 - Most popular AI provider',
      'anthropic': 'Claude 3.5 Sonnet, Opus, Haiku - Excellent reasoning',
      'google': 'Gemini Pro, Ultra - Google\'s AI models',
      'deepseek': 'DeepSeek Chat, Coder - Open source alternatives',
      'openrouter': 'Access to 100+ models through single API',
      'ollama': 'Run AI models locally on your machine',
      'lm_studio': 'Desktop app for running local AI models',
      'azure': 'Microsoft Azure OpenAI Service',
      'groq': 'Fast inference with Groq chips',
      'mistral': 'Mistral AI models',
    };
    return descriptions[providerId] || 'AI model provider';
  },

  // Open the wizard
  open() {
    this.isOpen = true;
    this.currentStep = 0;
    this.resetWizard();
  },

  // Close the wizard
  close() {
    this.isOpen = false;
    if (!this.isComplete) {
      // Return to welcome screen if not complete
    }
  },

  // Reset wizard data
  resetWizard() {
    this.selectedProvider = null;
    this.apiKey = '';
    this.selectedChatModel = null;
    this.selectedUtilModel = null;
    this.isValidating = false;
    this.validationError = null;
    this.isComplete = false;
  },

  // Navigate to specific step
  goToStep(step) {
    if (step >= 0 && step < this.totalSteps) {
      this.currentStep = step;
      this.validationError = null;
    }
  },

  // Next step
  nextStep() {
    if (this.currentStep < this.totalSteps - 1) {
      // Validate before moving to next step
      if (this.currentStep === 1 && !this.selectedProvider) {
        this.validationError = 'Please select a provider';
        return;
      }
      if (this.currentStep === 2 && !this.apiKey) {
        this.validationError = 'Please enter your API key';
        return;
      }
      if (this.currentStep === 3 && !this.selectedChatModel) {
        this.validationError = 'Please select at least a chat model';
        return;
      }

      this.currentStep++;
      this.validationError = null;
    }
  },

  // Previous step
  prevStep() {
    if (this.currentStep > 0) {
      this.currentStep--;
      this.validationError = null;
    }
  },

  // Select provider
  selectProvider(providerId) {
    this.selectedProvider = providerId;
    this.chatModels = this.getModelsForProvider(providerId, 'chat');
    this.utilModels = this.getModelsForProvider(providerId, 'util');
    this.selectedChatModel = null;
    this.selectedUtilModel = null;
  },

  // Get models for provider
  getModelsForProvider(providerId, type) {
    const models = {
      'openai': {
        'chat': [
          { id: 'gpt-4-turbo', name: 'GPT-4 Turbo', description: 'Latest GPT-4 with vision' },
          { id: 'gpt-4', name: 'GPT-4', description: 'Most capable model' },
          { id: 'gpt-3.5-turbo', name: 'GPT-3.5 Turbo', description: 'Fast and affordable' },
        ],
        'util': [
          { id: 'gpt-3.5-turbo', name: 'GPT-3.5 Turbo', description: 'Fast and affordable' },
        ],
      },
      'anthropic': {
        'chat': [
          { id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', description: 'Latest Claude' },
          { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', description: 'Most capable' },
          { id: 'claude-3-haiku-20240307', name: 'Claude 3 Haiku', description: 'Fast and affordable' },
        ],
        'util': [
          { id: 'claude-3-haiku-20240307', name: 'Claude 3 Haiku', description: 'Fast and affordable' },
        ],
      },
      'google': {
        'chat': [
          { id: 'gemini-1.5-pro', name: 'Gemini 1.5 Pro', description: 'Long context, multimodal' },
          { id: 'gemini-1.5-flash', name: 'Gemini 1.5 Flash', description: 'Fast and efficient' },
          { id: 'gemini-pro', name: 'Gemini Pro', description: 'Balanced performance' },
        ],
        'util': [
          { id: 'gemini-1.5-flash', name: 'Gemini 1.5 Flash', description: 'Fast and efficient' },
        ],
      },
      'deepseek': {
        'chat': [
          { id: 'deepseek-chat', name: 'DeepSeek Chat', description: 'Open source alternative' },
          { id: 'deepseek-coder', name: 'DeepSeek Coder', description: 'Specialized for code' },
        ],
        'util': [
          { id: 'deepseek-chat', name: 'DeepSeek Chat', description: 'Open source alternative' },
        ],
      },
      'openrouter': {
        'chat': [
          { id: 'anthropic/claude-3.5-sonnet', name: 'Claude 3.5 Sonnet', description: 'Via OpenRouter' },
          { id: 'openai/gpt-4-turbo', name: 'GPT-4 Turbo', description: 'Via OpenRouter' },
          { id: 'google/gemini-pro-1.5', name: 'Gemini Pro 1.5', description: 'Via OpenRouter' },
        ],
        'util': [
          { id: 'openai/gpt-3.5-turbo', name: 'GPT-3.5 Turbo', description: 'Via OpenRouter' },
        ],
      },
      'ollama': {
        'chat': [
          { id: 'llama3', name: 'Llama 3', description: 'Meta\'s latest model' },
          { id: 'mistral', name: 'Mistral', description: 'Mistral AI model' },
          { id: 'codellama', name: 'CodeLlama', description: 'For code generation' },
        ],
        'util': [
          { id: 'llama3', name: 'Llama 3', description: 'Meta\'s latest model' },
        ],
      },
      'lm_studio': {
        'chat': [
          { id: 'llama3', name: 'Llama 3', description: 'Meta\'s latest model' },
          { id: 'mistral', name: 'Mistral', description: 'Mistral AI model' },
          { id: 'phi3', name: 'Phi-3', description: 'Microsoft\'s small model' },
        ],
        'util': [
          { id: 'llama3', name: 'Llama 3', description: 'Meta\'s latest model' },
        ],
      },
    };

    return models[providerId]?.[type] || [];
  },

  // Validate API key
  async validateApiKey() {
    if (!this.apiKey || !this.selectedProvider) {
      this.validationError = 'Provider and API key are required';
      return false;
    }

    this.isValidating = true;
    this.validationError = null;

    try {
      // Save settings temporarily to test connection
      const settings = {
        chat_model_provider: this.selectedProvider,
        chat_model_name: this.selectedChatModel?.id || 'gpt-3.5-turbo',
        util_model_provider: this.selectedProvider,
        util_model_name: this.selectedUtilModel?.id || 'gpt-3.5-turbo',
      };

      // Build the env var name for the API key
      const apiKeyEnvVar = `${this.selectedProvider.toUpperCase()}_API_KEY`;

      // Save secrets and test connection
      const response = await sendJsonData('/api/secrets_set', {
        secrets: { [apiKeyEnvVar]: this.apiKey },
      });

      // Test the connection
      const testResult = await sendJsonData(API_ENDPOINTS.TEST_CONNECTION, {
        provider: this.selectedProvider,
      });

      this.isValidating = false;

      if (testResult && testResult.success) {
        return true;
      } else {
        this.validationError = testResult?.error || 'Failed to connect. Please check your API key.';
        return false;
      }
    } catch (e) {
      this.isValidating = false;
      this.validationError = e.message || 'Failed to validate API key';
      return false;
    }
  },

  // Complete the wizard
  async complete() {
    // Validate all steps
    if (!this.selectedProvider || !this.apiKey || !this.selectedChatModel) {
      this.validationError = 'Please complete all required steps';
      return;
    }

    this.isValidating = true;
    this.validationError = null;

    try {
      // Save the final configuration
      const settings = {
        chat_model_provider: this.selectedProvider,
        chat_model_name: this.selectedChatModel.id,
        util_model_provider: this.selectedProvider,
        util_model_name: this.selectedUtilModel?.id || this.selectedChatModel.id,
        browser_model_provider: this.selectedProvider,
        browser_model_name: this.selectedChatModel.id,
      };

      await sendJsonData(API_ENDPOINTS.SETTINGS_SAVE, settings);

      this.isComplete = true;
      this.isValidating = false;

      // Close wizard and reload
      setTimeout(() => {
        this.close();
        window.location.reload();
      }, 1500);

    } catch (e) {
      this.isValidating = false;
      this.validationError = e.message || 'Failed to save configuration';
    }
  },

  // Get progress percentage
  get progress() {
    return Math.round(((this.currentStep + 1) / this.totalSteps) * 100);
  },

  // Check if step is complete
  isStepComplete(step) {
    switch (step) {
    case 0: return true; // Welcome always complete
    case 1: return !!this.selectedProvider;
    case 2: return !!this.apiKey && !this.validationError;
    case 3: return !!this.selectedChatModel;
    case 4: return this.selectedProvider && this.selectedChatModel;
    default: return false;
    }
  },

  // Skip wizard (go to settings directly)
  skip() {
    this.close();
    // Open settings modal
    const settingsButton = document.getElementById('settings');
    if (settingsButton) {
      settingsButton.click();
    }
  },
};

// Create and export the store
const store = createStore('setupWizardStore', model);
export { store };
