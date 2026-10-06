#!/bin/bash
#SBATCH --job-name=uni_omni_demo
#SBATCH --partition=hubaotian
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --gpus-per-node=1
#SBATCH --cpus-per-task=25
#SBATCH --time=24:00:00
#SBATCH --output=/uni_omni_demo/slurm_%j.out
#SBATCH --error=uni_omni_demo/slurm_%j.err

# rm -f ~/.ssh/known_hosts


source ~/.bashrc
conda activate unimoe-tts

module load CUDA/12.4
module load ffmpeg/6.1-gcc-11.4.0 
module load pdsh/2.31-gcc-11.4.0
module load nccl/2.23.4-cuda-12.4


# 进入项目目录
cd path/to/Uni-MoE/Uni-MoE-TTS/train

# 获取主节点信息
export NCCL_TIMEOUT_MS=300000
export PYTHONPATH=path/to/Uni-MoE/Uni-MoE-TTS/train
export TOKENIZERS_PARALLELISM=false
export MASTER_ADDR="localhost"
export MASTER_PORT=12347
export GPUS_PER_NODE=1

echo "Job ID: $SLURM_JOB_ID"
echo "Number of nodes: $SLURM_NNODES"
echo "Master address: $MASTER_ADDR"
echo "Master port: $MASTER_PORT"
echo "Conda environment: $CONDA_DEFAULT_ENV"


# 验证GPU可用性
echo "Checking GPU availability on node $SLURM_NODEID..."
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}'); print(f'GPU count: {torch.cuda.device_count()}'); print(f'Current device: {torch.cuda.current_device() if torch.cuda.is_available() else \"N/A\"}')"


deepspeed --include localhost:0\
    --master_addr $MASTER_ADDR --master_port $MASTER_PORT \
    uni_omni/train/train_mem_speech.py \
    --deepspeed ./scripts/zero2.json \
    --model_name_or_path path/to/Qwen2.5-0.5B-Instruct \
    --version v1 \
    --data_path path/to/Uni-MoE/Uni-MoE-TTS/train/training_data/training_smp_1000.json \
    --mm_use_im_start_end False \
    --mm_use_im_patch_token False \
    --bf16 True \
    --output_dir output \
    --num_train_epochs 4 \
    --per_device_train_batch_size 1 \
    --per_device_eval_batch_size 2 \
    --gradient_accumulation_steps 8 \
    --save_strategy "steps" \
    --save_steps 1000 \
    --save_total_limit 3 \
    --learning_rate 8e-5 \
    --weight_decay 0. \
    --warmup_ratio 0.0 \
    --lr_scheduler_type "cosine" \
    --logging_steps 1 \
    --tf32 True \
    --model_max_length 2100 \
    --gradient_checkpointing False \
    --dataloader_num_workers 10 \
    --lazy_preprocess True \
    --report_to tensorboard \
    --tune_speech_generator True\
    --tune_speech_generator_only True\
    --speech_generator_type ar_ori_v2_new \
    --load_weight_from_qwen path/to/Model/Uni-MoE-TTS/from_model/speech_gen_ep2.bin \
    --expert_dir path/to/Model/Uni-MoE-TTS/training/experts \
    --codes_folder path/to/Uni-MoE/Uni-MoE-TTS/train \
    --transformer_num_blocks 24\
    --audio_mode "tts_pretrain"\
    --group_by_modality_length True
