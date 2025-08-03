# train.py
# Script to fine-tune the TinyLLaMA model on the cybersecurity dataset.

import torch
from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, TaskType
from trl import SFTTrainer

# --- Configuration ---
# Specifies the base model to be fine-tuned.
BASE_MODEL_NAME = "PY007/TinyLlama-1.1B-Chat-v1.0"
# Path to the training dataset created by the data_preprocessing.py script.
TRAIN_DATASET_PATH = "data/train_dataset.json"
# Path to the testing dataset for evaluation.
TEST_DATASET_PATH = "data/test_dataset.json"
# Directory where the fine-tuned model adapter will be saved.
OUTPUT_DIR = "./model/tinyllama-lora-tuned-adapter-cybersecurity"

# --- Tokenizer and Model Loading ---
# Load the tokenizer for the base model.
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME, trust_remote_code=True)
# Set the padding token to be the end-of-sentence token.
tokenizer.pad_token = tokenizer.eos_token

# Configure 4-bit quantization for memory efficiency.
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
)

# Load the base model with the quantization configuration.
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL_NAME,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
)

# --- LoRA Configuration ---
# Configure Low-Rank Adaptation (LoRA) for efficient fine-tuning.
lora_config = LoraConfig(
    r=8,
    lora_alpha=16,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type=TaskType.CAUSAL_LM,
)

# Apply LoRA to the model.
model = get_peft_model(model, lora_config)

# --- Data Loading and Formatting ---
# Load the training and testing datasets.
train_dataset = load_dataset('json', data_files=TRAIN_DATASET_PATH, split='train')

def formatting_prompts_func(example):
    """
    Formats the dataset examples into a structured prompt format for training.
    """
    output_texts = []
    for i in range(len(example['instruction'])):
        text = f"### Instruction:\n{example['instruction'][i]}\n\n### Response:\n{example['response'][i]}"
        output_texts.append(text)
    return output_texts

# --- Training ---
# Define the training arguments.
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=4,
    gradient_accumulation_steps=4,
    learning_rate=1e-4,
    num_train_epochs=3,
    fp16=True,
    logging_steps=10,
    save_strategy="epoch",
    report_to="none",
)

# Initialize the trainer.
trainer = SFTTrainer(
    model=model,
    train_dataset=train_dataset,
    args=training_args,
    formatting_func=formatting_prompts_func,
    tokenizer=tokenizer,
    max_seq_length=512,
)

# Start the training process.
trainer.train()

# --- Save the Model ---
# Save the fine-tuned LoRA adapter.
trainer.save_model(OUTPUT_DIR)
print(f"Model fine-tuning complete. Adapter saved to {OUTPUT_DIR}")
