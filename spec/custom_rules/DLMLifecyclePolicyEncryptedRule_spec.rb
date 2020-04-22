require 'spec_helper'
require 'cfn-model'
require 'cfn-nag/custom_rules/DLMLifecyclePolicyEncryptedRule'

describe DLMLifecyclePolicyEncryptedRule, :rule do
  expected_logical_resource_ids = %w[DLMLifecyclePolicy]

  context 'DLM LifecyclePolicy without CrossRegionCopyRules' do
    it 'returns empty list' do
      cfn_model = CfnParser.new.parse read_test_template(
        'yaml/dlm_lifecyclepolicy/dlm_lifecyclepolicy_no_crossregioncopyrules.yml'
      )

      actual_logical_resource_ids =
        DLMLifecyclePolicyEncryptedRule.new.audit_impl cfn_model

      expect(actual_logical_resource_ids).to eq %w[]
    end
  end

  context 'DLM LifecyclePolicy without encrypted set' do
    it 'returns logical resource id for offending DLM LifecyclePolicy' do
      cfn_model = CfnParser.new.parse read_test_template(
        'yaml/dlm_lifecyclepolicy/dlm_lifecyclepolicy_no_encrypted.yml'
      )

      actual_logical_resource_ids =
        DLMLifecyclePolicyEncryptedRule.new.audit_impl cfn_model

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end

  context 'DLM LifecyclePolicy with encrypted set to false' do
    it 'returns logical resource id for offending DLM LifecyclePolicy' do
      cfn_model = CfnParser.new.parse read_test_template(
        'yaml/dlm_lifecyclepolicy/dlm_lifecyclepolicy_encrypted_false.yml'
      )

      actual_logical_resource_ids =
        DLMLifecyclePolicyEncryptedRule.new.audit_impl cfn_model

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end

  context 'DLM LifecyclePolicy with encrypted set to true' do
    it 'returns empty list' do
      cfn_model = CfnParser.new.parse read_test_template(
        'yaml/dlm_lifecyclepolicy/dlm_lifecyclepolicy_encrypted_true.yml'
      )

      actual_logical_resource_ids =
        DLMLifecyclePolicyEncryptedRule.new.audit_impl cfn_model

      expect(actual_logical_resource_ids).to eq %w[]
    end
  end
end
