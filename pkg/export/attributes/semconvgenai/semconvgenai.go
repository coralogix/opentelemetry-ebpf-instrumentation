// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package semconvgenai

import "go.opentelemetry.io/otel/attribute"

const (
	GenAIConversationIDKey             = attribute.Key("gen_ai.conversation.id")
	GenAIDataSourceIDKey               = attribute.Key("gen_ai.data_source.id")
	GenAIEmbeddingsDimensionCountKey   = attribute.Key("gen_ai.embeddings.dimension.count")
	GenAIInputMessagesKey              = attribute.Key("gen_ai.input.messages")
	GenAIOperationNameKey              = attribute.Key("gen_ai.operation.name")
	GenAIOutputMessagesKey             = attribute.Key("gen_ai.output.messages")
	GenAIOutputTypeKey                 = attribute.Key("gen_ai.output.type")
	GenAIPromptNameKey                 = attribute.Key("gen_ai.prompt.name")
	GenAIProviderNameKey               = attribute.Key("gen_ai.provider.name")
	GenAIRequestChoiceCountKey         = attribute.Key("gen_ai.request.choice.count")
	GenAIRequestEncodingFormatsKey     = attribute.Key("gen_ai.request.encoding_formats")
	GenAIRequestFrequencyPenaltyKey    = attribute.Key("gen_ai.request.frequency_penalty")
	GenAIRequestMaxTokensKey           = attribute.Key("gen_ai.request.max_tokens")
	GenAIRequestModelKey               = attribute.Key("gen_ai.request.model")
	GenAIRequestPresencePenaltyKey     = attribute.Key("gen_ai.request.presence_penalty")
	GenAIRequestSeedKey                = attribute.Key("gen_ai.request.seed")
	GenAIRequestStopSequencesKey       = attribute.Key("gen_ai.request.stop_sequences")
	GenAIRequestTemperatureKey         = attribute.Key("gen_ai.request.temperature")
	GenAIRequestTopKKey                = attribute.Key("gen_ai.request.top_k")
	GenAIRequestTopPKey                = attribute.Key("gen_ai.request.top_p")
	GenAIResponseFinishReasonsKey      = attribute.Key("gen_ai.response.finish_reasons")
	GenAIResponseIDKey                 = attribute.Key("gen_ai.response.id")
	GenAIResponseModelKey              = attribute.Key("gen_ai.response.model")
	GenAISystemInstructionsKey         = attribute.Key("gen_ai.system_instructions")
	GenAITokenTypeKey                  = attribute.Key("gen_ai.token.type")
	GenAIToolCallArgumentsKey          = attribute.Key("gen_ai.tool.call.arguments")
	GenAIToolCallIDKey                 = attribute.Key("gen_ai.tool.call.id")
	GenAIToolCallResultKey             = attribute.Key("gen_ai.tool.call.result")
	GenAIToolDefinitionsKey            = attribute.Key("gen_ai.tool.definitions")
	GenAIToolNameKey                   = attribute.Key("gen_ai.tool.name")
	GenAIToolTypeKey                   = attribute.Key("gen_ai.tool.type")
	GenAIUsageInputTokensKey           = attribute.Key("gen_ai.usage.input_tokens")
	GenAIUsageOutputTokensKey          = attribute.Key("gen_ai.usage.output_tokens")
	McpMethodNameKey                   = attribute.Key("mcp.method.name")
	McpProtocolVersionKey              = attribute.Key("mcp.protocol.version")
	McpResourceURIKey                  = attribute.Key("mcp.resource.uri")
	McpSessionIDKey                    = attribute.Key("mcp.session.id")
	OpenAIRequestServiceTierKey        = attribute.Key("openai.request.service_tier")
	OpenAIResponseServiceTierKey       = attribute.Key("openai.response.service_tier")
	OpenAIResponseSystemFingerprintKey = attribute.Key("openai.response.system_fingerprint")
)

var (
	GenAIOutputTypeJSON         = GenAIOutputTypeKey.String("json")
	GenAIOutputTypeText         = GenAIOutputTypeKey.String("text")
	GenAIProviderNameAWSBedrock = GenAIProviderNameKey.String("aws.bedrock")
	GenAIProviderNameAnthropic  = GenAIProviderNameKey.String("anthropic")
	GenAIProviderNameCohere     = GenAIProviderNameKey.String("cohere")
	GenAIProviderNameGCPGemini  = GenAIProviderNameKey.String("gcp.gemini")
	GenAIProviderNameOpenAI     = GenAIProviderNameKey.String("openai")
)

func GenAIConversationID(val string) attribute.KeyValue {
	return GenAIConversationIDKey.String(val)
}

func GenAIDataSourceID(val string) attribute.KeyValue {
	return GenAIDataSourceIDKey.String(val)
}

func GenAIEmbeddingsDimensionCount(val int) attribute.KeyValue {
	return GenAIEmbeddingsDimensionCountKey.Int(val)
}

func GenAIRequestChoiceCount(val int) attribute.KeyValue {
	return GenAIRequestChoiceCountKey.Int(val)
}

func GenAIRequestEncodingFormats(val ...string) attribute.KeyValue {
	return GenAIRequestEncodingFormatsKey.StringSlice(val)
}

func GenAIRequestFrequencyPenalty(val float64) attribute.KeyValue {
	return GenAIRequestFrequencyPenaltyKey.Float64(val)
}

func GenAIRequestMaxTokens(val int) attribute.KeyValue {
	return GenAIRequestMaxTokensKey.Int(val)
}

func GenAIRequestModel(val string) attribute.KeyValue {
	return GenAIRequestModelKey.String(val)
}

func GenAIRequestPresencePenalty(val float64) attribute.KeyValue {
	return GenAIRequestPresencePenaltyKey.Float64(val)
}

func GenAIRequestSeed(val int) attribute.KeyValue {
	return GenAIRequestSeedKey.Int(val)
}

func GenAIRequestStopSequences(val ...string) attribute.KeyValue {
	return GenAIRequestStopSequencesKey.StringSlice(val)
}

func GenAIRequestTemperature(val float64) attribute.KeyValue {
	return GenAIRequestTemperatureKey.Float64(val)
}

func GenAIRequestTopK(val float64) attribute.KeyValue {
	return GenAIRequestTopKKey.Float64(val)
}

func GenAIRequestTopP(val float64) attribute.KeyValue {
	return GenAIRequestTopPKey.Float64(val)
}

func GenAIResponseFinishReasons(val ...string) attribute.KeyValue {
	return GenAIResponseFinishReasonsKey.StringSlice(val)
}

func GenAIResponseID(val string) attribute.KeyValue {
	return GenAIResponseIDKey.String(val)
}

func GenAIResponseModel(val string) attribute.KeyValue {
	return GenAIResponseModelKey.String(val)
}

func GenAIUsageInputTokens(val int) attribute.KeyValue {
	return GenAIUsageInputTokensKey.Int(val)
}

func GenAIUsageOutputTokens(val int) attribute.KeyValue {
	return GenAIUsageOutputTokensKey.Int(val)
}

func OpenAIResponseServiceTier(val string) attribute.KeyValue {
	return OpenAIResponseServiceTierKey.String(val)
}

func OpenAIResponseSystemFingerprint(val string) attribute.KeyValue {
	return OpenAIResponseSystemFingerprintKey.String(val)
}
